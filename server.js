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

const resolveUploadPath = (p) => {
  if (!p) return null;
  const uploadsDir = path.join(__dirname, 'uploads');
  try {
    if (path.isAbsolute(p)) {
      if (fs.existsSync(p)) return p;
      const fb = path.join(uploadsDir, path.basename(p));
      if (fs.existsSync(fb)) return fb;
      return null;
    }
    const abs = path.join(__dirname, p);
    if (fs.existsSync(abs)) return abs;
    const alt = path.join(uploadsDir, path.basename(p));
    if (fs.existsSync(alt)) return alt;
  } catch (_) {}
  return null;
};

const backfillMemoFiles = () => {
  try {
    const db = store.get();
    let changed = false;
    db.memos.forEach((m) => {
      if (!m.file && m.filePath) {
        const abs = resolveUploadPath(m.filePath);
        if (abs && fs.existsSync(abs)) {
          try {
            const buf = fs.readFileSync(abs);
            m.file = {
              base64: buf.toString('base64'),
              mime: (function(){
                const ext = path.extname(abs).toLowerCase();
                if (ext === '.pdf') return 'application/pdf';
                return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
              })(),
              filename: m.originalFileName || path.basename(abs),
              size: buf.length
            };
            changed = true;
          } catch (_) {}
        }
      }
    });
    if (changed) store.save(db);
  } catch (_) {}
};

backfillMemoFiles();

const purgeUploads = () => {
  try {
    const dir = path.join(__dirname, 'uploads');
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {}
  ensureDir(path.join(__dirname, 'uploads'));
};

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
  name: 'memoo.sid',
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: String(process.env.NODE_ENV).toLowerCase() === 'production',
  }
}));

// Expose logged-in user to templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Multer setup for DOCX uploads
const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  limits: { fileSize: parseInt(process.env.UPLOAD_MAX_BYTES || '10485760', 10) },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/pdf'
    ];
    const name = file.originalname.toLowerCase();
    if (allowed.includes(file.mimetype) || name.endsWith('.docx') || name.endsWith('.pdf')) {
      cb(null, true);
    } else {
      cb(new Error('Only .docx or .pdf files are allowed'));
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
  const authEnabled = String(process.env.FIREBASE_AUTH_ENABLED || 'false').toLowerCase() === 'true';
  if (authEnabled) {
    return res.render('login', { title: 'Login', error: 'Firebase Auth is enabled. Use Firebase sign-in.' });
  }
  res.render('login', { title: 'Login', error: null });
});

// GET signup page
app.get('/signup', (req, res) => {
  res.render('signup', { title: 'Signup', error: null });
});

// POST login
app.post('/login', async (req, res) => {
  const authEnabled = String(process.env.FIREBASE_AUTH_ENABLED || 'false').toLowerCase() === 'true';
  if (authEnabled) return res.status(404).send('Local login disabled. Use Firebase sign-in.');
  const { email, password } = req.body;
  const users = await store.listUsersAsync();
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
    const authEnabled = String(process.env.FIREBASE_AUTH_ENABLED || 'false').toLowerCase() === 'true';
    if (!authEnabled) return res.status(404).send('Firebase Auth disabled on server');
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

    const users = await store.listUsersAsync();
    let user = users.find(u => u.email === email);

  if (!user) {
    // Signup path: require a valid role to create user
    if (!requestedRole || !['hr', 'manager', 'admin'].includes(requestedRole)) {
      return res.status(400).send('Role is required (hr, manager, admin) for new accounts.');
    }

    // Admin restrictions: allowlist and seat cap
    if (requestedRole === 'admin') {
      const ADMIN_MAX = parseInt(process.env.ADMIN_MAX || '2', 10);
      const ADMIN_ALLOWLIST_DISABLED = String(process.env.ADMIN_ALLOWLIST_DISABLE || 'true').toLowerCase() === 'true';
      const ADMIN_ALLOWLIST = ADMIN_ALLOWLIST_DISABLED ? [] : String(process.env.ADMIN_ALLOWLIST || '')
        .split(',')
        .map(s => s.trim().toLowerCase())
        .filter(Boolean);

      const adminCount = users.filter(u => u.role === 'admin').length;
      if (adminCount >= ADMIN_MAX) {
        return res.status(403).send('Admin seats are full. Contact existing admin.');
      }
      if (ADMIN_ALLOWLIST.length && !ADMIN_ALLOWLIST.includes(email)) {
        return res.status(403).send('This email is not authorized for admin role.');
      }
    }

      user = { email, role: requestedRole, password: null };
      await store.saveUserAsync(user);
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
    res.status(401).send('Invalid or expired token. Check Firebase project mismatch or clock skew.');
  }
});

app.post('/sessionLogout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// POST signup
app.post('/signup', async (req, res) => {
  try {
    const authEnabled = String(process.env.FIREBASE_AUTH_ENABLED || 'false').toLowerCase() === 'true';
    if (authEnabled) {
      return res.render('signup', { title: 'Signup', error: 'Firebase Auth is enabled. Create account via Firebase and use session login.' });
    }
    let { email, password, role, passwordConfirm } = req.body;
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
    if ((passwordConfirm || '') !== password) {
      return res.render('signup', { title: 'Signup', error: 'Passwords do not match.' });
    }

    // Domain enforcement unless ALLOW_ANY_DOMAIN=true
    const allowAny = String(process.env.ALLOW_ANY_DOMAIN || 'true').toLowerCase() === 'true';
    const companyConfig = getCompanyByEmail(email);
    if (!allowAny && !companyConfig) {
      return res.render('signup', { title: 'Signup', error: 'Your email domain is not configured. Please contact admin to add your company domain.' });
    }

    const users = await store.listUsersAsync();
    const existing = users.find(u => u.email === email);
    if (existing) {
      return res.render('signup', { title: 'Signup', error: 'An account already exists for this email.' });
    }

    // Admin restrictions: allowlist and seat cap
    if (role === 'admin') {
      const ADMIN_MAX = parseInt(process.env.ADMIN_MAX || '2', 10);
      const ADMIN_ALLOWLIST_DISABLED = String(process.env.ADMIN_ALLOWLIST_DISABLE || 'true').toLowerCase() === 'true';
      const ADMIN_ALLOWLIST = ADMIN_ALLOWLIST_DISABLED ? [] : String(process.env.ADMIN_ALLOWLIST || '')
        .split(',')
        .map(s => s.trim().toLowerCase())
        .filter(Boolean);

      const adminCount = users.filter(u => u.role === 'admin').length;
      if (adminCount >= ADMIN_MAX) {
        return res.render('signup', { title: 'Signup', error: 'Admin seats are full. Contact existing admin.' });
      }
      if (ADMIN_ALLOWLIST.length && !ADMIN_ALLOWLIST.includes(email)) {
        return res.render('signup', { title: 'Signup', error: 'This email is not authorized for admin role.' });
      }
    }

    const hash = await bcrypt.hash(password, 10);
    const newUser = { email, password: hash, role };
    await store.saveUserAsync(newUser);

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
app.get('/hr', requireLogin, async (req, res) => {
  if (req.session.user.role !== 'hr') return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: 'hr', user: req.session.user });

  const statusFilter = (req.query.status || '').trim().toLowerCase();
  let memos = await store.listMemosByHrAsync(req.session.user.email);
  if (['open', 'waiting', 'closed'].includes(statusFilter)) {
    memos = memos.filter((m) => (m.status || 'open') === statusFilter);
  }
  memos = memos.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
  res.render('hr', { title: 'HR Dashboard', memos, statusFilter, user: req.session.user, baseUrl });
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
    const filePath = path.join('uploads', req.file.filename);
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
    try {
      const absUpload = path.join(__dirname, 'uploads', req.file.filename);
      const buf = fs.readFileSync(absUpload);
      memo.file = {
        base64: buf.toString('base64'),
        mime: req.file.mimetype || 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        filename: memo.originalFileName,
        size: buf.length
      };
    } catch (_) {}

    await store.addMemoAsync(memo);

    const companyConfig = getCompanyByEmail(hrEmail);
    if (companyConfig) {
      try {
        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
        await mailer.sendMemoCreated({ memo, baseUrl, companyConfig });
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
app.post('/hr/memo/:id/status', requireLogin, async (req, res) => {
  if (req.session.user.role !== 'hr') return res.status(403).send('Forbidden');

  const { id } = req.params;
  const { status } = req.body;
  const allowed = ['open', 'waiting', 'closed'];
  if (!allowed.includes((status || '').toLowerCase())) return res.status(400).send('Invalid status');

  const memo = await store.getMemoByIdAsync(id);
  if (!memo) return res.status(404).send('Memo not found');

  await store.updateMemoStatusAsync(id, status.toLowerCase());
  res.redirect('/hr');
});

// Manager Dashboard
app.get('/manager', requireLogin, async (req, res) => {
  if (req.session.user.role !== 'manager') return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: 'manager', user: req.session.user });

  const email = req.session.user.email;
  const statusFilter = (req.query.status || '').trim().toLowerCase();
  let memos = await store.listMemosByManagerAsync(email);
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
  const memo = await store.getMemoByIdAsync(id);
  if (!memo) return res.status(404).send('Memo not found');
  if (viewerEmail !== memo.managerEmail && viewerEmail !== memo.hrEmail) {
    return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: null, user: req.session.user });
  }

  let html = '<p><em>Unable to render document preview.</em></p>';
  const abs = resolveUploadPath(memo.filePath);
  const mimeGuess = memo.file?.mime || (function(){
    const name = (memo.originalFileName || memo.filePath || '').toLowerCase();
    if (name.endsWith('.pdf')) return 'application/pdf';
    return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  })();
  if (mimeGuess === 'application/pdf') {
    const src = `/memo/${id}/file`;
    html = `<iframe src="${src}" title="PDF preview" style="width:100%;height:600px;border:0"></iframe>`;
  } else {
    try {
      if (abs) {
        const buffer = fs.readFileSync(abs);
        const result = await mammoth.convertToHtml({ buffer });
        html = result.value || html;
      }
    } catch (err) {
      console.error('Mammoth conversion error:', err);
    }
    if (!abs && memo.file && memo.file.base64) {
      try {
        const buffer = Buffer.from(memo.file.base64, 'base64');
        const result = await mammoth.convertToHtml({ buffer });
        html = result.value || html;
      } catch (_) {}
    }
  }

  const isManagerViewer = viewerEmail === memo.managerEmail;
  const isHRViewer = viewerEmail === memo.hrEmail;
  res.render('memo', { title: `Memo: ${memo.title}`, memo, docHtml: html, viewerEmail, isManagerViewer, isHRViewer, prefillMessage });
});

app.get('/memo/:id/download', requireLogin, async (req, res) => {
  const { id } = req.params;
  const viewerEmail = req.session.user.email;
  const memo = await store.getMemoByIdAsync(id);
  if (!memo) return res.status(404).send('Memo not found');
  if (viewerEmail !== memo.managerEmail && viewerEmail !== memo.hrEmail) {
    return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: null, user: req.session.user });
  }
  const abs = resolveUploadPath(memo.filePath);
  if (abs && fs.existsSync(abs)) {
    return res.download(abs, memo.originalFileName);
  }
  if (memo.file && memo.file.base64) {
    const buffer = Buffer.from(memo.file.base64, 'base64');
    res.setHeader('Content-Type', memo.file.mime || 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${memo.file.filename || memo.originalFileName || 'memo.docx'}"`);
    return res.end(buffer);
  }
  return res.status(404).send('Source file not found');
});

app.get('/memo/:id/file', requireLogin, async (req, res) => {
  const { id } = req.params;
  const viewerEmail = req.session.user.email;
  const memo = await store.getMemoByIdAsync(id);
  if (!memo) return res.status(404).send('Memo not found');
  if (viewerEmail !== memo.managerEmail && viewerEmail !== memo.hrEmail) {
    return res.status(403).render('forbidden', { title: 'Access Restricted', roleRequired: null, user: req.session.user });
  }
  const abs = resolveUploadPath(memo.filePath);
  if (abs && fs.existsSync(abs)) {
    const stream = fs.createReadStream(abs);
    const ext = path.extname(abs).toLowerCase();
    const mime = memo.file?.mime || (ext === '.pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Disposition', `inline; filename="${memo.originalFileName || path.basename(abs)}"`);
    return stream.pipe(res);
  }
  if (memo.file && memo.file.base64) {
    const buffer = Buffer.from(memo.file.base64, 'base64');
    res.setHeader('Content-Type', memo.file.mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${memo.file.filename || memo.originalFileName || 'memo'}"`);
    return res.end(buffer);
  }
  return res.status(404).send('Source file not found');
});

// Reply to Memo
app.post('/memo/:id/reply', requireLogin, async (req, res) => {
  const { id } = req.params;
  const { message } = req.body;
  const memo = await store.getMemoByIdAsync(id);
  if (!memo) return res.status(404).send('Memo not found');

  const senderEmail = req.session.user.email;
  let senderRole = req.session.user.role;

  if (senderRole !== 'manager' && senderRole !== 'hr') return res.status(403).send('Forbidden');
  if (!message || !message.trim()) return res.status(400).send('Reply message cannot be empty.');

  const reply = { sender: senderRole, email: senderEmail, message: message.trim(), createdAt: new Date().toISOString() };
  await store.addReplyAsync(id, reply);

  const companyConfig = getCompanyByEmail(senderRole === 'hr' ? memo.managerEmail : memo.hrEmail);
  if (companyConfig) {
    try {
      const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
      await mailer.sendReplyNotification({ memo, reply, baseUrl, companyConfig });
    } catch (err) {
      console.error('Email send error (reply notification):', err);
    }
  } else {
    console.warn(`No SMTP config found for reply recipient. Notification email not sent.`);
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

// --- Admin: Admin users management ---
app.get('/admin/users', requireLogin, requireRole('admin'), async (req, res) => {
  const users = await store.listUsersAsync();
  const admins = users.filter(u => u.role === 'admin');
  res.render('admin_users', { title: 'Manage Admins', admins, message: null, currentEmail: req.session.user.email, adminMax: parseInt(process.env.ADMIN_MAX || '2', 10) });
});

app.post('/admin/admins/add', requireLogin, requireRole('admin'), async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email || !email.includes('@')) {
      const users = await store.listUsersAsync();
      const admins = users.filter(u => u.role === 'admin');
      return res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'Valid admin email is required.' }, currentEmail: req.session.user.email, adminMax: parseInt(process.env.ADMIN_MAX || '2', 10) });
    }

    const users = await store.listUsersAsync();
    const admins = users.filter(u => u.role === 'admin');
    const ADMIN_MAX = parseInt(process.env.ADMIN_MAX || '2', 10);
    if (admins.length >= ADMIN_MAX) {
      return res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'Admin seats are full.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
    }
    if (users.find(u => u.email === email)) {
      return res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'User already exists.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
    }

    await store.saveUserAsync({ email, role: 'admin', password: null });
    const updated = await store.listUsersAsync();
    const updatedAdmins = updated.filter(u => u.role === 'admin');
    res.render('admin_users', { title: 'Manage Admins', admins: updatedAdmins, message: { type: 'success', text: 'Admin added.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
  } catch (err) {
    console.error('Add admin error:', err);
    const users = await store.listUsersAsync();
    const admins = users.filter(u => u.role === 'admin');
    res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'Failed to add admin.' }, currentEmail: req.session.user.email, adminMax: parseInt(process.env.ADMIN_MAX || '2', 10) });
  }
});

app.post('/admin/admins/:email/delete', requireLogin, requireRole('admin'), async (req, res) => {
  try {
    const target = (req.params.email || '').trim().toLowerCase();
    let users = await store.listUsersAsync();
    const admins = users.filter(u => u.role === 'admin');
    const ADMIN_MAX = parseInt(process.env.ADMIN_MAX || '2', 10);

    if (!target || !admins.find(a => a.email === target)) {
      return res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'Admin not found.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
    }
    // Prevent removing yourself and prevent going below 1 admin
    if (target === req.session.user.email) {
      return res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'You cannot remove your own admin account.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
    }
    if (admins.length <= 1) {
      return res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'At least one admin must remain.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
    }

    const exists = users.find(u => u.role === 'admin' && u.email === target);
    if (!exists) {
      return res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'Admin not found.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
    }
    await store.deleteUserAsync(target);
    const updated = await store.listUsersAsync();
    const updatedAdmins = updated.filter(u => u.role === 'admin');
    res.render('admin_users', { title: 'Manage Admins', admins: updatedAdmins, message: { type: 'success', text: 'Admin removed.' }, currentEmail: req.session.user.email, adminMax: ADMIN_MAX });
  } catch (err) {
    console.error('Delete admin error:', err);
    const users = await store.listUsersAsync();
    const admins = users.filter(u => u.role === 'admin');
    res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'Failed to remove admin.' }, currentEmail: req.session.user.email, adminMax: parseInt(process.env.ADMIN_MAX || '2', 10) });
  }
});

app.post('/admin/reset', requireLogin, requireRole('admin'), async (req, res) => {
  try {
    const currentEmail = (req.session.user?.email || '').trim().toLowerCase();
    const users = await store.listUsersAsync();
    const keep = users.find(u => u.email === currentEmail && u.role === 'admin');
    const kept = keep ? [keep] : [];

    await store.purgeAllAsync();
    for (const u of kept) { await store.saveUserAsync(u); }
    purgeUploads();

    const admins = kept;
    res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'success', text: 'All memos and users cleared. Current admin retained. Uploads purged.' }, currentEmail: currentEmail, adminMax: parseInt(process.env.ADMIN_MAX || '2', 10) });
  } catch (err) {
    console.error('Reset error:', err);
    const users = await store.listUsersAsync();
    const admins = users.filter(u => u.role === 'admin');
    res.render('admin_users', { title: 'Manage Admins', admins, message: { type: 'error', text: 'Failed to reset data.' }, currentEmail: req.session.user.email, adminMax: parseInt(process.env.ADMIN_MAX || '2', 10) });
  }
});

app.post('/admin/reset-all', requireLogin, requireRole('admin'), async (req, res) => {
  try {
    await store.purgeAllAsync();
    purgeUploads();
  } catch (err) {
    console.error('Reset-all error:', err);
  }
  try {
    req.session.destroy(() => res.redirect('/login'));
  } catch (_) {
    res.redirect('/login');
  }
});
