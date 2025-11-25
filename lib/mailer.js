const path = require('path');
const ejs = require('ejs');
const nodemailer = require('nodemailer');
require('dotenv').config();

function createTransport() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE } = process.env;
  if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
    return nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: (SMTP_SECURE || 'false').toLowerCase() === 'true',
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
  }
  // Fallback to direct transport (not recommended) to avoid blocking dev usage
  return nodemailer.createTransport({
    // This will try to send without SMTP; many environments will reject.
    // Configure SMTP in .env for reliable delivery.
    sendmail: true,
    newline: 'unix',
    path: '/usr/sbin/sendmail'
  });
}

const transporter = createTransport();

async function render(templateName, data) {
  const filePath = path.join(__dirname, '..', 'views', 'email', `${templateName}.ejs`);
  return await ejs.renderFile(filePath, data, { async: true });
}

async function sendMemoCreated({ memo, baseUrl }) {
  const subject = `New Memo: ${memo.title}`;
  const html = await render('memo_created', {
    memo,
    baseUrl,
    openUrl: `${baseUrl}/memo/${memo.id}?email=${encodeURIComponent(memo.managerEmail)}`
  });
  const from = process.env.MAIL_FROM || 'Memoo <no-reply@memoo.local>';
  const to = memo.managerEmail;
  const cc = memo.hrEmail ? memo.hrEmail : undefined;
  await transporter.sendMail({ from, to, cc, subject, html });
}

async function sendReplyNotification({ memo, reply, baseUrl }) {
  const to = reply.sender === 'manager' ? memo.hrEmail : memo.managerEmail;
  if (!to) return;
  const subject = `New Reply • ${memo.title}`;
  const html = await render('reply_notification', {
    memo,
    reply,
    baseUrl,
    openUrl: `${baseUrl}/memo/${memo.id}`,
    thread: memo.replies
  });
  const from = process.env.MAIL_FROM || 'Memoo <no-reply@memoo.local>';
  await transporter.sendMail({ from, to, subject, html });
}

module.exports = { sendMemoCreated, sendReplyNotification };