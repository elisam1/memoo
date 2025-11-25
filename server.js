const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const mammoth = require('mammoth');
const { nanoid } = require('nanoid');
const store = require('./lib/store');
const mailer = require('./lib/mailer');
require('dotenv').config();

// Ensure needed directories exist
const ensureDir = (p) => {
  if (!fs.existsSync(p)) {
    fs.mkdirSync(p, { recursive: true });
  }
};

ensureDir(path.join(__dirname, 'uploads'));
ensureDir(path.join(__dirname, 'public'));
ensureDir(path.join(__dirname, 'data'));

const expressLayouts = require('express-ejs-layouts');
const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Multer setup for DOCX uploads
const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  fileFilter: (req, file, cb) => {
    const allowed = ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowed.includes(file.mimetype) || file.originalname.toLowerCase().endsWith('.docx')) {
      cb(null, true);
    } else {
      cb(new Error('Only .docx files are allowed'));
    }
  }
});

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Memoo — Login' });
});

// HR dashboard
app.get('/hr', (req, res) => {
  const db = store.get();
  const statusFilter = (req.query.status || '').trim().toLowerCase();
  let memos = db.memos;
  if (['open', 'waiting', 'closed'].includes(statusFilter)) {
    memos = memos.filter(m => (m.status || 'open') === statusFilter);
  }
  memos = memos.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.render('hr', { title: 'HR Dashboard', memos, statusFilter });
});

app.post('/hr/memo', upload.single('file'), async (req, res) => {
  try {
    const { title, description, managerEmail, hrEmail, importance } = req.body;
    if (!title || !managerEmail || !hrEmail || !req.file) {
      return res.status(400).send('HR Email, Title, Manager Email, and .docx file are required.');
    }

    const id = nanoid(8);
    const filePath = req.file.path;
    const memo = {
      id,
      title,
      description: description || '',
      managerEmail: managerEmail.trim().toLowerCase(),
      hrEmail: hrEmail.trim().toLowerCase(),
      importance: (importance || 'normal').toLowerCase(),
      status: 'open',
      filePath,
      originalFileName: req.file.originalname,
      createdAt: new Date().toISOString(),
      replies: []
    };

    const db = store.get();
    db.memos.push(memo);
    store.save(db);
    // Send notification email to manager (CC HR)
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    try {
      await mailer.sendMemoCreated({ memo, baseUrl });
    } catch (mailErr) {
      console.error('Email send error (memo created):', mailErr);
    }
    res.redirect('/hr');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to create memo. ' + err.message);
  }
});

// HR updates memo status
app.post('/hr/memo/:id/status', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const allowed = ['open', 'waiting', 'closed'];
  if (!allowed.includes((status || '').toLowerCase())) {
    return res.status(400).send('Invalid status');
  }
  const db = store.get();
  const memo = db.memos.find(m => m.id === id);
  if (!memo) return res.status(404).send('Memo not found');
  memo.status = status.toLowerCase();
  store.save(db);
  res.redirect('/hr');
});

// Manager dashboard — requires email query
app.get('/manager', (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  const db = store.get();
  const statusFilter = (req.query.status || '').trim().toLowerCase();
  let memos = email ? db.memos.filter(m => m.managerEmail === email) : [];
  if (['open', 'waiting', 'closed'].includes(statusFilter)) {
    memos = memos.filter(m => (m.status || 'open') === statusFilter);
  }
  res.render('manager', { title: 'Manager Dashboard', email, memos, statusFilter });
});

// View memo and optionally reply (if accessed by manager with email)
app.get('/memo/:id', async (req, res) => {
  const { id } = req.params;
  const viewerEmail = (req.query.email || '').trim().toLowerCase();
  const prefillMessage = (req.query.prefill || '').toString();
  const autoReply = (req.query.reply || '') === '1';
  const db = store.get();
  const memo = db.memos.find(m => m.id === id);
  if (!memo) return res.status(404).send('Memo not found');

  let html = '<p><em>Unable to render document preview.</em></p>';
  try {
    const buffer = fs.readFileSync(memo.filePath);
    const result = await mammoth.convertToHtml({ buffer });
    html = result.value || html;
  } catch (err) {
    console.error('Mammoth conversion error:', err);
  }

  const isManagerViewer = viewerEmail && viewerEmail === memo.managerEmail;
  const isHRViewer = viewerEmail && viewerEmail === memo.hrEmail;
  res.render('memo', { title: `Memo: ${memo.title}`, memo, docHtml: html, viewerEmail, isManagerViewer, isHRViewer, prefillMessage, autoReply });
});

app.post('/memo/:id/reply', (req, res) => {
  const { id } = req.params;
  const { email, message } = req.body;
  const db = store.get();
  const memo = db.memos.find(m => m.id === id);
  if (!memo) return res.status(404).send('Memo not found');
  const senderEmail = (email || '').trim().toLowerCase();
  let senderRole = null;
  if (senderEmail === memo.managerEmail) senderRole = 'manager';
  if (senderEmail === memo.hrEmail) senderRole = 'hr';
  if (!senderRole) return res.status(400).send('Only the assigned manager or HR can reply to this memo.');
  if (!message || !message.trim()) {
    return res.status(400).send('Reply message cannot be empty.');
  }
  memo.replies.push({
    sender: senderRole,
    email: senderEmail,
    message: message.trim(),
    createdAt: new Date().toISOString()
  });
  store.save(db);
  // Notify the other party that a reply was received
  const reply = memo.replies[memo.replies.length - 1];
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  mailer.sendReplyNotification({ memo, reply, baseUrl }).catch(err => {
    console.error('Email send error (reply notification):', err);
  });
  const redirectEmail = senderRole === 'manager' ? memo.managerEmail : memo.hrEmail;
  res.redirect(`/memo/${id}?email=${encodeURIComponent(redirectEmail)}`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});