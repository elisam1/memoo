const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const mammoth = require('mammoth');
const { nanoid } = require('nanoid');
const expressLayouts = require('express-ejs-layouts');
const session = require('express-session');
const bcrypt = require('bcrypt');
require('dotenv').config();

const store = require('./lib/store');
const mailer = require('./lib/mailer');
const { getCompanyByEmail, loadCompanies, saveCompanies } = require('./lib/companyHelper');
const { verifyIdToken } = require('./lib/firebaseAdmin');

// Ensure needed directories exist
const ensureDir = (p) => {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
};
ensureDir(path.join(__dirname, 'uploads'));
ensureDir(path.join(__dirname, 'public'));
ensureDir(path.join(__dirname, 'data'));

// App setup
const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecretkey',
  resave: false,
  saveUninitialized: false,
}));

// Expose logged-in user to templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Multer setup for DOCX uploads
const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  fileFilter: (req, file, cb) => {
    const allowed = [
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    if (allowed.includes(file.mimetype) || file.originalname.toLowerCase().endsWith('.docx')) {
      cb(null, true);
    } else {
      cb(new Error('Only .docx files are allowed'));
    }
  }
});

// --- Middleware: Protect routes ---
const requireLogin = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  next();
};

const requireRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role) {
    return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: role, user: req.session.user || null });
  }
  next();
};

// --- Routes ---

// Landing page redirects based on session
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.redirect('/login');
});

// GET login page
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: null });
});

// GET signup page
app.get('/signup', (req, res) => {
  res.render('signup', { title: 'Signup', error: null });
});

// POST login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const users = store.getUsers();
  const user = users.find(u => u.email === email.trim().toLowerCase());

  if (!user) {
    return res.render('login', { title: 'Login', error: 'Invalid email or password' });
  }

  // Enforce domain by companies.json unless ALLOW_ANY_DOMAIN=true
  const allowAny = String(process.env.ALLOW_ANY_DOMAIN || 'true').toLowerCase() === 'true';
  const companyConfig = getCompanyByEmail(email.trim().toLowerCase());
  if (!allowAny && !companyConfig) {
    return res.render('login', { title: 'Login', error: 'Your email domain is not configured. Please contact admin to add your company domain.' });
  }

  // Support bcrypt-hashed passwords and plaintext (for dev/demo)
  let ok = false;
  try {
    if (user.password && user.password.startsWith('$2')) {
      ok = await bcrypt.compare(password, user.password);
    } else {
      ok = user.password === password;
    }
  } catch (e) {
    ok = false;
  }

  if (!ok) {
    return res.render('login', { title: 'Login', error: 'Invalid email or password' });
  }

  // Store user in session
  req.session.user = user;
  res.redirect('/home');
});

// Establish session via Firebase ID token (client-side auth)
app.post('/sessionLogin', async (req, res) => {
  try {
    const idToken = req.body.idToken;
    const requestedRole = (req.body.role || '').trim().toLowerCase();
    if (!idToken) return res.status(400).send('Missing idToken');

    const decoded = await verifyIdToken(idToken);
    const email = (decoded.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Token has no email');

    // Domain enforcement unless ALLOW_ANY_DOMAIN=true
    const allowAny = String(process.env.ALLOW_ANY_DOMAIN || 'true').toLowerCase() === 'true';
    const companyConfig = getCompanyByEmail(email);
    if (!allowAny && !companyConfig) {
      return res.status(403).send('Your email domain is not configured. Please contact admin to add your company domain.');
    }

    const users = store.getUsers();
    let user = users.find(u => u.email === email);

    if (!user) {
      // Signup path: require a valid role to create user
      if (!requestedRole || !['hr', 'manager', 'admin'].includes(requestedRole)) {
        return res.status(400).send('Role is required (hr, manager, admin) for new accounts.');
      }
      user = { email, role: requestedRole, password: null };
      users.push(user);
      store.saveUsers(users);
    }

    // Ignore requested role on login for existing users; server is the source of truth
    req.session.user = user;
    res.redirect('/home');
  } catch (err) {
    console.error('Session login error:', err);
    const msg = String(err && err.message || '');
    if (msg.includes('Firebase Admin not initialized')) {
      return res.status(500).send('Server auth not configured: set Firebase service account in .env');
    }
    res.status(401).send('Invalid or expired token.');
  }
});

app.post('/sessionLogout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// POST signup
app.post('/signup', async (req, res) => {
  try {
    let { email, password, role } = req.body;
    email = (email || '').trim().toLowerCase();
    role = (role || '').trim().toLowerCase();

    if (!email || !password || !role) {
      return res.render('signup', { title: 'Signup', error: 'Email, password and role are required.' });
    }
    if (!['hr', 'manager', 'admin'].includes(role)) {
      return res.render('signup', { title: 'Signup', error: 'Role must be HR, Manager, or Admin.' });
    }
    if (password.length < 6) {
      return res.render('signup', { title: 'Signup', error: 'Password must be at least 6 characters.' });
    }

    // Domain enforcement unless ALLOW_ANY_DOMAIN=true
    const allowAny = String(process.env.ALLOW_ANY_DOMAIN || 'true').toLowerCase() === 'true';
    const companyConfig = getCompanyByEmail(email);
    if (!allowAny && !companyConfig) {
      return res.render('signup', { title: 'Signup', error: 'Your email domain is not configured. Please contact admin to add your company domain.' });
    }

    const users = store.getUsers();
    const existing = users.find(u => u.email === email);
    if (existing) {
      return res.render('signup', { title: 'Signup', error: 'An account already exists for this email.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const newUser = { email, password: hash, role };
    users.push(newUser);
    store.saveUsers(users);

    // Auto login after signup
    req.session.user = newUser;
    res.redirect('/home');
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).render('signup', { title: 'Signup', error: 'Failed to create account.' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Home dashboard
app.get('/home', requireLogin, (req, res) => {
  res.render('home', { title: 'Home Dashboard', user: req.session.user });
});

// HR Dashboard
app.get('/hr', requireLogin, (req, res) => {
  if (req.session.user.role !== 'hr') return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: 'hr', user: req.session.user });

  const db = store.get();
  const statusFilter = (req.query.status || '').trim().toLowerCase();
  let memos = db.memos;
  if (['open', 'waiting', 'closed'].includes(statusFilter)) {
    memos = memos.filter((m) => (m.status || 'open') === statusFilter);
  }
  memos = memos.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.render('hr', { title: 'HR Dashboard', memos, statusFilter, user: req.session.user });
});

// Create Memo
app.post('/hr/memo', requireLogin, upload.single('file'), async (req, res) => {
  if (req.session.user.role !== 'hr') return res.status(403).send('Forbidden');

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

    const companyConfig = getCompanyByEmail(hrEmail);
    if (companyConfig) {
      try {
        await mailer.sendMemoCreated({ memo, baseUrl: `${req.protocol}://${req.get('host')}`, companyConfig });
      } catch (err) {
        console.error('Email send error:', err);
      }
    } else {
      console.warn(`No SMTP config found for ${hrEmail}. Memo saved but email not sent.`);
    }

    res.redirect('/hr');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to create memo. ' + err.message);
  }
});

// Update Memo Status
app.post('/hr/memo/:id/status', requireLogin, (req, res) => {
  if (req.session.user.role !== 'hr') return res.status(403).send('Forbidden');

  const { id } = req.params;
  const { status } = req.body;
  const allowed = ['open', 'waiting', 'closed'];
  if (!allowed.includes((status || '').toLowerCase())) return res.status(400).send('Invalid status');

  const db = store.get();
  const memo = db.memos.find((m) => m.id === id);
  if (!memo) return res.status(404).send('Memo not found');

  memo.status = status.toLowerCase();
  store.save(db);
  res.redirect('/hr');
});

// Manager Dashboard
app.get('/manager', requireLogin, (req, res) => {
  if (req.session.user.role !== 'manager') return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: 'manager', user: req.session.user });

  const email = req.session.user.email;
  const db = store.get();
  const statusFilter = (req.query.status || '').trim().toLowerCase();
  let memos = db.memos.filter((m) => m.managerEmail === email);
  if (['open', 'waiting', 'closed'].includes(statusFilter)) {
    memos = memos.filter((m) => (m.status || 'open') === statusFilter);
  }
  res.render('manager', { title: 'Manager Dashboard', email, memos, statusFilter, user: req.session.user });
});

// View Memo
app.get('/memo/:id', requireLogin, async (req, res) => {
  const { id } = req.params;
  const viewerEmail = req.session.user.email;
  const prefillMessage = (req.query.prefill || '').toString();
  const db = store.get();
  const memo = db.memos.find((m) => m.id === id);
  if (!memo) return res.status(404).send('Memo not found');

  let html = '<p><em>Unable to render document preview.</em></p>';
  try {
    const buffer = fs.readFileSync(memo.filePath);
    const result = await mammoth.convertToHtml({ buffer });
    html = result.value || html;
  } catch (err) {
    console.error('Mammoth conversion error:', err);
  }

  const isManagerViewer = viewerEmail === memo.managerEmail;
  const isHRViewer = viewerEmail === memo.hrEmail;
  res.render('memo', { title: `Memo: ${memo.title}`, memo, docHtml: html, viewerEmail, isManagerViewer, isHRViewer, prefillMessage });
});

// Reply to Memo
app.post('/memo/:id/reply', requireLogin, async (req, res) => {
  const { id } = req.params;
  const { message } = req.body;
  const db = store.get();
  const memo = db.memos.find((m) => m.id === id);
  if (!memo) return res.status(404).send('Memo not found');

  const senderEmail = req.session.user.email;
  let senderRole = req.session.user.role;

  if (senderRole !== 'manager' && senderRole !== 'hr') return res.status(403).send('Forbidden');
  if (!message || !message.trim()) return res.status(400).send('Reply message cannot be empty.');

  const reply = { sender: senderRole, email: senderEmail, message: message.trim(), createdAt: new Date().toISOString() };
  memo.replies.push(reply);
  store.save(db);

  const companyConfig = getCompanyByEmail(senderRole === 'hr' ? memo.managerEmail : memo.hrEmail);
  if (companyConfig) {
    try {
      await mailer.sendReplyNotification({ memo, reply, baseUrl: `${req.protocol}://${req.get('host')}`, companyConfig });
    } catch (err) {
      console.error('Email send error (reply notification):', err);
    }
  }

  const redirectEmail = senderRole === 'manager' ? memo.managerEmail : memo.hrEmail;
  res.redirect(`/memo/${id}?prefill=${encodeURIComponent(message)}`);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}/`));

// --- Admin: Domain management ---
app.get('/admin/domains', requireLogin, requireRole('admin'), (req, res) => {
  const companies = loadCompanies();
  res.render('admin_domains', { title: 'Manage Domains', companies, message: null });
});

app.post('/admin/domains/add', requireLogin, requireRole('admin'), (req, res) => {
  try {
    const { name, domain, smtp_host, smtp_port, smtp_secure, smtp_user, smtp_pass } = req.body;
    const companies = loadCompanies();
    const d = (domain || '').trim().toLowerCase();
    if (!d || companies.find(c => c.domain.toLowerCase() === d)) {
      return res.render('admin_domains', { title: 'Manage Domains', companies, message: { type: 'error', text: 'Invalid or duplicate domain.' } });
    }
    const port = parseInt(smtp_port, 10) || 0;
    const secure = String(smtp_secure).toLowerCase() === 'true';
    if (!smtp_host || !port || !smtp_user || !smtp_pass) {
      return res.render('admin_domains', { title: 'Manage Domains', companies, message: { type: 'error', text: 'SMTP host, port, user, and password are required.' } });
    }
    companies.push({ name: (name || '').trim() || d, domain: d, smtp: { host: smtp_host.trim(), port, secure, auth: { user: smtp_user.trim(), pass: smtp_pass } } });
    saveCompanies(companies);
    res.render('admin_domains', { title: 'Manage Domains', companies, message: { type: 'success', text: 'Domain added.' } });
  } catch (err) {
    console.error('Add domain error:', err);
    const companies = loadCompanies();
    res.render('admin_domains', { title: 'Manage Domains', companies, message: { type: 'error', text: 'Failed to add domain.' } });
  }
});

app.post('/admin/domains/:domain/delete', requireLogin, requireRole('admin'), (req, res) => {
  try {
    const target = (req.params.domain || '').toLowerCase();
    let companies = loadCompanies();
    const before = companies.length;
    companies = companies.filter(c => c.domain.toLowerCase() !== target);
    if (companies.length === before) {
      return res.render('admin_domains', { title: 'Manage Domains', companies, message: { type: 'error', text: 'Domain not found.' } });
    }
    saveCompanies(companies);
    res.render('admin_domains', { title: 'Manage Domains', companies, message: { type: 'success', text: 'Domain deleted.' } });
  } catch (err) {
    console.error('Delete domain error:', err);
    const companies = loadCompanies();
    res.render('admin_domains', { title: 'Manage Domains', companies, message: { type: 'error', text: 'Failed to delete domain.' } });
  }
});
