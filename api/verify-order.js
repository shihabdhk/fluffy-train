// api/verify-order.js

// Using 'require' is the standard way to import in Vercel Serverless Functions
const fetch = require('node-fetch');
const admin = require('firebase-admin');

// NOTE: We initialize 'admin' lazily (only after passing initial security checks)
let adminApp = null;

// ⭐⭐⭐ RATE LIMIT CONFIG (Vercel-Safe In-Memory) ⭐⭐⭐
const RATE_LIMIT = 5; // Max 5 requests
const WINDOW = 60 * 1000; // 1 minute
const ipHits = {}; // Cache of IP → Timestamps array

function isRateLimited(ip) {
    const now = Date.now();

    if (!ipHits[ip]) {
        ipHits[ip] = [];
    }

    // Remove timestamps older than the time window
    ipHits[ip] = ipHits[ip].filter(ts => ts > now - WINDOW);

    // Block if exceeds limit
    if (ipHits[ip].length >= RATE_LIMIT) {
        return true;
    }

    // Add current request timestamp
    ipHits[ip].push(now);
    return false;
}

// --- CONFIGURATION ---
const APP_ID = process.env.FIREBASE_PROJECT_ID || 'bafsdjackets';

// --- ENV PARSE ---
function getServiceAccount() {
    try {
        let rawVar = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
        if (!rawVar) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_JSON env var");

        const serviceAccount = JSON.parse(rawVar);
        if (serviceAccount.private_key) {
            serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
        }
        return serviceAccount;
    } catch (e) {
        console.error("FATAL: Could not parse Service Account JSON.", e);
        return null; 
    }
}

// --- FIREBASE INIT (Lazy Load) ---
function getFirebase() {
    if (adminApp) return adminApp;

    if (!admin.apps.length) {
        const serviceAccount = getServiceAccount();
        if (!serviceAccount) throw new Error('SERVER_CONFIG_ERROR');

        try {
            adminApp = admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        } catch (e) {
            if (!(e.errorInfo && e.errorInfo.code === 'app/already-exists')) {
                console.error("Firebase init failed:", e);
                throw new Error('SERVER_CONFIG_ERROR');
            }
            adminApp = admin.app();
        }
    } else {
        adminApp = admin.app();
    }

    return adminApp;
}

// --- VALIDATION ---
function validateOrder(data) {
    const errors = [];

    if (!data.fullName || !/^[a-zA-Z\s]{2,15}$/.test(data.fullName))
        errors.push("Invalid Name: Must be 2-15 letters only.");

    if (!data.phoneNumber || !/^(013|014|015|016|017|018|019)[0-9]{8}$/.test(data.phoneNumber))
        errors.push("Invalid Phone: Must be 11 digits starting with 01x.");

    if (!data.rollNumber || !/^[0-9]{6}$/.test(data.rollNumber))
        errors.push("Invalid Roll Number: Must be 6 digits.");

    const allowedDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    if (!data.email || !data.email.includes('@')) {
        errors.push("Invalid Email.");
    } else {
        const domain = data.email.split('@')[1];
        if (!allowedDomains.includes(domain)) {
            errors.push("Invalid Email Domain: Only Gmail, Yahoo, Hotmail, Outlook allowed.");
        }
    }

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

module.exports = async (req, res) => {

    // --- 1. CORS ---
    const allowedOrigins = [
        'https://bafsdjackets.online',
        'https://www.bafsdjackets.online',
        'https://bafsdjackets.web.app',
        'https://bafsdjackets.firebaseapp.com'
    ];

    const origin = req.headers.origin;
    const allowOrigin = allowedOrigins.includes(origin)
        ? origin
        : 'https://bafsdjackets.online';

    res.setHeader('Access-Control-Allow-Origin', allowOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).send('');
    if (req.method !== 'POST') return res.status(405).json({ message: 'Method Not Allowed' });

    // ⭐⭐⭐ --- 2. RATE LIMIT BEFORE ANYTHING --- ⭐⭐⭐
    const ip =
        req.headers['x-real-ip'] ||
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress ||
        'unknown';

    if (isRateLimited(ip)) {
        return res.status(429).json({
            success: false,
            message: "Too many requests. Slow down bro 💀"
        });
    }

    try {
        // Parse request body (Vercel pre-parses JSON)
        const data = req.body;
        const { hCaptchaToken, orderId, userId, ...rawFormData } = data;

        // --- CAPTCHA CHECK ---
        if (!hCaptchaToken) {
            return res.status(400).json({ message: 'Missing Captcha Token' });
        }

        const SECRET_KEY = process.env.HCAPTCHA_SECRET_KEY;
        if (!SECRET_KEY) {
            console.error("Missing HCAPTCHA_SECRET_KEY");
            return res.status(500).json({ message: 'Server Configuration Error' });
        }

        const verifyResp = await fetch('https://api.hcaptcha.com/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${SECRET_KEY}&response=${hCaptchaToken}`
        });

        const hcaptchaResult = await verifyResp.json();

        if (!hcaptchaResult.success) {
            return res.status(403).json({ success: false, message: 'Bot verification failed.' });
        }

        // --- FIREBASE INIT ---
        const adminInstance = getFirebase();
        const db = adminInstance.firestore();

        // --- STORE STATUS CHECK ---
        const settingsSnap = await db.doc('settings/storeStatus').get();
        if (settingsSnap.exists && settingsSnap.data().takingOrders === false) {
            return res.status(403).json({ success: false, message: 'Orders are currently closed.' });
        }

        // --- VALIDATION ---
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
            return res.status(400).json({
                success: false,
                message: 'Invalid Data',
                errors: validationErrors
            });
        }

        // --- DATABASE WRITE ---
        const finalOrderId = orderId || db.collection('temp').doc().id;

        const privateRef = db.doc(`artifacts/${APP_ID}/public/data/orders/${finalOrderId}`);
        const publicRef  = db.doc(`artifacts/${APP_ID}/public/data/tracking/${finalOrderId}`);

        await db.runTransaction(async (tx) => {
            const doc = await tx.get(privateRef);

            if (doc.exists) throw new Error("SECURITY_CONFLICT: Order ID already exists.");

            tx.set(privateRef, {
                ...formData,
                batch: 'Batch 26',
                status: 'PENDING_CASH',
                paymentMethod: 'cash',
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                userId: userId || 'anonymous',
                verifiedBy: 'Vercel-Backend',
                publicRef: finalOrderId
            });

            tx.set(publicRef, {
                id: finalOrderId,
                fullName: formData.fullName,
                rollNumber: formData.rollNumber,
                status: 'PENDING_CASH',
                size: formData.size,
                batch: 'Batch 26',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        return res.status(200).json({
            success: true,
            message: "Order placed successfully.",
            orderId: finalOrderId
        });

    } catch (err) {
        console.error("Error:", err);

        if (err.message.includes("SECURITY_CONFLICT"))
            return res.status(409).json({ success: false, message: "Order ID collision. Try again." });

        if (err.message.includes("SERVER_CONFIG_ERROR"))
            return res.status(500).json({ success: false, message: "Server Configuration Error." });

        return res.status(500).json({
            success: false,
            message: `Internal Server Error: ${err.message}`
        });
    }
};
