// api/verify-order.js

// Using 'require' is the standard way to import in Vercel Serverless Functions
const fetch = require('node-fetch');
const admin = require('firebase-admin'); // Import Admin SDK outside for cleaner lazy initialization
// NOTE: We initialize 'admin' lazily (only after passing initial security checks)
let adminApp = null; // Use a new variable name to hold the initialized app

// --- CONFIGURATION ---
const APP_ID = process.env.FIREBASE_PROJECT_ID || 'bafsdjackets';

// --- HELPER: ROBUST ENVIRONMENT VARIABLE PARSING ---
function getServiceAccount() {
    try {
        let rawVar = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
        if (!rawVar) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON env var");

        const serviceAccount = JSON.parse(rawVar);
        
        if (serviceAccount.private_key) {
            // This is the CRUCIAL line that converts the escaped newlines in the ENV var 
            // back into actual newlines required by the Admin SDK.
            serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
        }
        return serviceAccount;
    } catch (e) {
        console.error("FATAL: Could not parse Service Account JSON.", e);
        return null; 
    }
}

// --- HELPER: LAZY LOAD FIREBASE (ANTI-SPAM OPTIMIZATION) ---
function getFirebase() {
    if (adminApp) return adminApp; // Return initialized app if it exists
    
    if (!admin.apps.length) {
        const serviceAccount = getServiceAccount();
        if (!serviceAccount) throw new Error('SERVER_CONFIG_ERROR');
        
        try {
            // Initialize and store the app instance
            adminApp = admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        } catch (e) {
            // Netlify-style check for an already existing app
            if (e.errorInfo && e.errorInfo.code !== 'app/already-exists') {
                console.error("Firebase Init Failed during lazy load:", e);
                throw new Error('SERVER_CONFIG_ERROR');
            }
            // If already exists, we can still try to get the existing app
            adminApp = admin.app();
        }
    } else {
        // If apps already exist (e.g., in a warm start), get the default app
        adminApp = admin.app();
    }
    return adminApp;
}

// --- SECURITY: SERVER-SIDE VALIDATION ---
function validateOrder(data) {
    const errors = [];

    // 1. Name: Letters only, 2-15 chars
    if (!data.fullName || !/^[a-zA-Z\s]{2,15}$/.test(data.fullName)) {
        errors.push("Invalid Name: Must be 2-15 letters only.");
    }

    // 2. Phone: Bangladeshi Format
    if (!data.phoneNumber || !/^(013|014|015|016|017|018|019)[0-9]{8}$/.test(data.phoneNumber)) {
        errors.push("Invalid Phone: Must be 11 digits starting with 01x.");
    }

    // 3. Roll: Exactly 6 digits
    if (!data.rollNumber || !/^[0-9]{6}$/.test(data.rollNumber)) {
        errors.push("Invalid Roll Number: Must be 6 digits.");
    }

    // 4. Email: Allowed Domains only
    const allowedDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    if (!data.email || !data.email.includes('@')) {
        errors.push("Invalid Email.");
    } else {
        const domain = data.email.split('@')[1];
        if (!allowedDomains.includes(domain)) {
            errors.push("Invalid Email Domain: Only Gmail, Yahoo, Hotmail, Outlook allowed.");
        }
    }

    // 5. Enums (Size, Section, Group)
    const validSizes = ['S', 'M', 'L', 'XL', '2XL'];
    const validSections = [
        'Platinum', 'Vector', 'Horizon', 'Zenith', 'Don', 'Falcon', 
        'Itrium', 'Jewel', 'Equity', 'Galaxy', 'Mars', 'Cassiopeia', 
        'Orion', 'Silicon'
    ];
    const validGroups = ['Science', 'Commerce', 'Arts'];

    if (!validSizes.includes(data.size)) errors.push("Invalid Size.");
    if (!validSections.includes(data.section)) errors.push("Invalid Section.");
    if (!validGroups.includes(data.group)) errors.push("Invalid Group.");

    return errors;
}

/**
 * Vercel Serverless Function Handler (Express.js style)
 * @param {import('http').IncomingMessage} req The request object
 * @param {import('http').ServerResponse} res The response object
 */
module.exports = async (req, res) => { // <--- CHANGE 1: Vercel Export

    // --- 1. CORS CONFIGURATION (Using Vercel's res.setHeader) ---
    const allowedOrigins = [
        'https://bafsdjackets.online',          
        'https://www.bafsdjackets.online',      
        'https://bafsdjackets.web.app',         
        'https://bafsdjackets.firebaseapp.com'
    ];
    
    const origin = req.headers.origin; // Vercel uses req.headers
    const allowOrigin = allowedOrigins.includes(origin) ? origin : 'https://bafsdjackets.online';

    // Set CORS headers for all responses
    res.setHeader('Access-Control-Allow-Origin', allowOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { // <--- CHANGE 2: Handle OPTIONS pre-flight
        // Use res.status().send() for Vercel
        return res.status(200).send(''); 
    }
    
    if (req.method !== 'POST') { // <--- CHANGE 3: Method check
        // Use res.status().json() for Vercel
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        // Vercel pre-parses the body for POST requests with Content-Type: application/json
        const data = req.body; // <--- CHANGE 4: Use req.body directly
        const { hCaptchaToken, orderId, userId, ...rawFormData } = data;
        
        // --- 2. ANTI-SPAM: CAPTCHA CHECK (Fast Fail) ---
        if (!hCaptchaToken) {
            return res.status(400).json({ message: 'Missing Captcha Token' });
        }

        const SECRET_KEY = process.env.HCAPTCHA_SECRET_KEY;
        if (!SECRET_KEY) {
            console.error("Server Config Error: Missing HCAPTCHA_SECRET_KEY");
            return res.status(500).json({ message: 'Server Configuration Error' });
        }

        const verificationURL = 'https://api.hcaptcha.com/siteverify';
        const verifyResp = await fetch(verificationURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${SECRET_KEY}&response=${hCaptchaToken}`
        });

        const hcaptchaResult = await verifyResp.json();

        if (!hcaptchaResult.success) {
            return res.status(403).json({ success: false, message: 'Bot verification failed.' });
        }
        
        // --- 3. INITIALIZE FIREBASE (Only runs after Captcha is human-verified) ---
        const adminInstance = getFirebase();
        const db = adminInstance.firestore();

        // --- 4. SECURITY CHECK: STORE STATUS ---
        const settingsRef = db.doc('settings/storeStatus');
        const settingsSnap = await settingsRef.get();
        
        if (settingsSnap.exists && settingsSnap.data().takingOrders === false) {
             return res.status(403).json({ success: false, message: 'Orders are currently closed.' });
        }

        // --- 5. SANITIZATION & VALIDATION ---
        const formData = {
            fullName: (rawFormData.fullName || '').trim(),
            rollNumber: (rawFormData.rollNumber || '').trim(),
            phoneNumber: (rawFormData.phoneNumber || '').trim(),
            email: (rawFormData.email || '').trim(),
            size: rawFormData.size,
            section: rawFormData.section,
            group: rawFormData.group
        };

        const validationErrors = validateOrder(formData);
        if (validationErrors.length > 0) {
            return res.status(400).json({ success: false, message: 'Invalid Data', errors: validationErrors });
        }

        // --- 6. SECURE DATABASE WRITE (Transaction Check + Write) ---
        const finalOrderId = orderId || db.collection('temp').doc().id; 

        // PATH A: Private Data
        const privateRef = db.doc(`artifacts/${APP_ID}/public/data/orders/${finalOrderId}`);
        const privateData = {
            fullName: formData.fullName,
            rollNumber: formData.rollNumber,
            phoneNumber: formData.phoneNumber,
            email: formData.email,
            size: formData.size,
            section: formData.section,
            group: formData.group,
            batch: 'Batch 26',
            status: 'PENDING_CASH',
            paymentMethod: 'cash',
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            userId: userId || 'anonymous',
            verifiedBy: 'Vercel-Backend', // Updated to Vercel
            publicRef: finalOrderId
        };

        // PATH B: Public Tracking Data
        const publicRef = db.doc(`artifacts/${APP_ID}/public/data/tracking/${finalOrderId}`);
        const publicData = {
            id: finalOrderId,
            rollNumber: formData.rollNumber,
            fullName: formData.fullName,
            status: 'PENDING_CASH',
            size: formData.size,
            batch: 'Batch 26',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        };

        await db.runTransaction(async (transaction) => {
            const doc = await transaction.get(privateRef);
            
            // SECURITY: If the ID exists, we ABORT to prevent overwriting an existing order.
            if (doc.exists) {
                throw new Error("SECURITY_CONFLICT: Order ID already exists.");
            }

            // If safe, write both documents
            transaction.set(privateRef, privateData);
            transaction.set(publicRef, publicData);
        });

        // <--- CHANGE 5: Final Success Response
        return res.status(200).json({ success: true, message: 'Order placed successfully.', orderId: finalOrderId });

    } catch (error) {
        console.error('Error processing order:', error);
        
        // Handle specific server config error during lazy load
        if (error.message.includes("SERVER_CONFIG_ERROR")) {
            return res.status(500).json({ success: false, message: 'Server Configuration Error.' });
        }

        // Handle the specific Security Conflict error (Order Overwrite attempt)
        if (error.message.includes("SECURITY_CONFLICT")) {
            return res.status(409).json({ success: false, message: 'Order ID collision. Please try again.' });
        }

        // <--- CHANGE 6: General Error Response
        return res.status(500).json({ success: false, message: `Internal Server Error: ${error.message}` });
    }
};