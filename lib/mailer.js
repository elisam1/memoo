const nodemailer = require('nodemailer');
const { getFirestore } = require('./firebaseAdmin');

/**
 * Creates a Nodemailer transporter using the company's SMTP config.
 * @param {Object} companyConfig - { host, port, secure, auth: { user, pass } }
 */
function createTransporter(companyConfig) {
  if (!companyConfig || !companyConfig.auth || !companyConfig.host) {
    throw new Error('Invalid company SMTP configuration');
  }

  return nodemailer.createTransport({
    host: companyConfig.host,
    port: companyConfig.port,
    secure: companyConfig.secure || false,
    auth: {
      user: companyConfig.auth.user,
      pass: companyConfig.auth.pass
    }
  });
}

/**
 * Send email when a new memo is created
 * @param {Object} options - { memo, baseUrl, companyConfig }
 */
async function sendMemoCreated({ memo, baseUrl, companyConfig }) {
  const useFirebase = String(process.env.FIREBASE_EMAIL_ENABLED || 'false').toLowerCase() === 'true';
  const mailFrom = process.env.MAIL_FROM || (companyConfig?.auth?.user || 'memoo@localhost');
  const html = `
      <p>Hello,</p>
      <p>A new memo has been created and assigned to you.</p>
      <p><strong>Title:</strong> ${memo.title}</p>
      <p><strong>Description:</strong> ${memo.description || 'No description'}</p>
      <p><strong>Importance:</strong> ${(memo.importance || 'normal').toUpperCase()}</p>
      <p><a href="${baseUrl}/memo/${memo.id}?email=${encodeURIComponent(memo.managerEmail)}">View Memo</a></p>
      <p>Best,<br>HR Team</p>
    `;
  if (useFirebase) {
    const db = getFirestore();
    if (db) {
      await db.collection('mail').add({
        to: memo.managerEmail,
        replyTo: memo.hrEmail,
        message: { subject: `[Memoo] New Memo: ${memo.title}`, html },
      });
      return;
    }
  }
  const transporter = createTransporter(companyConfig);
  await transporter.sendMail({ from: mailFrom, replyTo: memo.hrEmail, to: memo.managerEmail, subject: `[Memoo] New Memo: ${memo.title}`, html });
}

/**
 * Send email notification when a reply is added
 * @param {Object} options - { memo, reply, baseUrl, companyConfig }
 */
async function sendReplyNotification({ memo, reply, baseUrl, companyConfig }) {
  const useFirebase = String(process.env.FIREBASE_EMAIL_ENABLED || 'false').toLowerCase() === 'true';
  const mailFrom = process.env.MAIL_FROM || (companyConfig?.auth?.user || 'memoo@localhost');
  const recipient = reply.sender === 'hr' ? memo.managerEmail : memo.hrEmail;
  const html = `
      <p>Hello,</p>
      <p>A new reply has been added to the memo "<strong>${memo.title}</strong>".</p>
      <p><strong>From:</strong> ${reply.sender.toUpperCase()} (${reply.email})</p>
      <p><strong>Message:</strong></p>
      <p>${reply.message}</p>
      <p><a href="${baseUrl}/memo/${memo.id}?email=${encodeURIComponent(recipient)}">View Memo</a></p>
      <p>Best,<br>Memoo System</p>
    `;
  if (useFirebase) {
    const db = getFirestore();
    if (db) {
      await db.collection('mail').add({
        to: recipient,
        replyTo: reply.email,
        message: { subject: `[Memoo] New Reply on Memo: ${memo.title}`, html },
      });
      return;
    }
  }
  const transporter = createTransporter(companyConfig);
  await transporter.sendMail({ from: mailFrom, replyTo: reply.email, to: recipient, subject: `[Memoo] New Reply on Memo: ${memo.title}`, html });
}

module.exports = {
  sendMemoCreated,
  sendReplyNotification
};
