const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

// Initialize Firebase Admin SDK using a service account JSON from env
// Set FIREBASE_SERVICE_ACCOUNT_JSON to the JSON string of the service account
// Optionally set FIREBASE_PROJECT_ID if not present in the service account
let initialized = false;
function initAdmin() {
  if (initialized) return admin;
  const svcJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const svcFile = process.env.FIREBASE_SERVICE_ACCOUNT_FILE;
  const svcBase64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
  if (!svcJson && !svcFile && !svcBase64) {
    console.warn('Firebase Admin service account not set (JSON, FILE, or BASE64). Token verification disabled.');
    initialized = true;
    return admin;
  }
  try {
    let serviceAccount = null;
    if (svcFile) {
      const filePath = path.resolve(process.cwd(), svcFile);
      const raw = fs.readFileSync(filePath, 'utf-8');
      serviceAccount = JSON.parse(raw);
    } else if (svcBase64) {
      const raw = Buffer.from(String(svcBase64), 'base64').toString('utf-8');
      serviceAccount = JSON.parse(raw);
    } else {
      serviceAccount = JSON.parse(svcJson);
    }
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: serviceAccount.project_id || process.env.FIREBASE_PROJECT_ID,
    });
    initialized = true;
    return admin;
  } catch (err) {
    console.error('Failed to initialize Firebase Admin:', err);
    initialized = true;
    return admin;
  }
}

async function verifyIdToken(idToken) {
  initAdmin();
  if (!admin.apps.length) {
    throw new Error('Firebase Admin not initialized; set FIREBASE_SERVICE_ACCOUNT_JSON');
  }
  return admin.auth().verifyIdToken(idToken);
}

module.exports = {
  initAdmin,
  verifyIdToken,
};
