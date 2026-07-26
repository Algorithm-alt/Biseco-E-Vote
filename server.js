require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const crypto = require('crypto');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const rateLimit = require('express-rate-limit');
const db = require('./config/db');
const { generateCode, generateCSRFToken, sanitizeInput } = require('./utils');

const SAFE_TABLES = ['users','elections','positions','candidates','votes','audit_logs','announcements','voter_election_access'];
const SAFE_COLUMNS = {
  users: ['id','code','password','role','has_voted','totp_secret','totp_enabled','email','created_at'],
  elections: ['id','name','description','status','start_date','end_date','logo_url','primary_color','secondary_color','results_published','created_at'],
  positions: ['id','election_id','name','description','sort_order','created_at'],
  candidates: ['id','position_id','name','photo','manifesto','sort_order','created_at'],
  votes: ['id','election_id','position_id','candidate_id','voter_hash','receipt_hash','vote_type','created_at'],
  audit_logs: ['id','admin_id','admin_code','action','details','ip_address','created_at'],
  announcements: ['id','title','content','is_active','priority','created_at'],
  voter_election_access: ['id','voter_id','election_id']
};

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 4000;

let wsClients = new Set();
wss.on('connection', (ws, req) => {
  const cookies = (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, ...rest] = c.trim().split('=');
    if (k) acc[k.trim()] = rest.join('=').trim();
    return acc;
  }, {});
  const sessionCookie = cookies['connect.sid'];
  if (!sessionCookie) {
    ws.close(4001, 'Authentication required');
    return;
  }
  const rawValue = sessionCookie.startsWith('s:') ? sessionCookie.slice(2) : sessionCookie;
  const sessionId = rawValue.split('.')[0];
  if (sessionId) {
    sessionStore.get(sessionId, (err, session) => {
      if (err || !session || !session.user) {
        ws.close(4001, 'Invalid session');
        return;
      }
      wsClients.add(ws);
      ws.on('close', () => wsClients.delete(ws));
      ws.on('error', () => wsClients.delete(ws));
    });
  } else {
    wsClients.add(ws);
    ws.on('close', () => wsClients.delete(ws));
    ws.on('error', () => wsClients.delete(ws));
  }
});

function broadcastVoteUpdate(data) {
  const msg = JSON.stringify(data);
  wsClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) client.send(msg);
  });
}
app.set('broadcastVoteUpdate', broadcastVoteUpdate);

async function autoSetup() {
  try {
    const [tables] = await db.query("SHOW TABLES LIKE 'users'");
    if (tables.length > 0) {
      const [count] = await db.query('SELECT COUNT(*) as cnt FROM users WHERE role = "admin"');
      if (count[0].cnt > 0) {
        await migrateDB();
        return;
      }
    }

    await db.query(`CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      code VARCHAR(10) NOT NULL UNIQUE,
      password VARCHAR(255) DEFAULT NULL,
      role ENUM('admin','voter') DEFAULT 'voter',
      has_voted TINYINT(1) DEFAULT 0,
      totp_secret VARCHAR(255) DEFAULT NULL,
      totp_enabled TINYINT(1) DEFAULT 0,
      pin VARCHAR(255) DEFAULT NULL,
      email VARCHAR(255) DEFAULT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.query(`CREATE TABLE elections (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(200) NOT NULL,
      description TEXT,
      status ENUM('upcoming','active','closed') DEFAULT 'upcoming',
      start_date DATETIME,
      end_date DATETIME,
      logo_url VARCHAR(500) DEFAULT NULL,
      primary_color VARCHAR(7) DEFAULT NULL,
      secondary_color VARCHAR(7) DEFAULT NULL,
      results_published TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.query(`CREATE TABLE positions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      election_id INT NOT NULL,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      sort_order INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE
    )`);

    await db.query(`CREATE TABLE candidates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      position_id INT NOT NULL,
      name VARCHAR(100) NOT NULL,
      photo VARCHAR(500) DEFAULT '/images/placeholder.png',
      manifesto TEXT,
      sort_order INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (position_id) REFERENCES positions(id) ON DELETE CASCADE
    )`);

    await db.query(`CREATE TABLE votes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      election_id INT NOT NULL,
      position_id INT NOT NULL,
      candidate_id INT NOT NULL,
      voter_hash VARCHAR(255) NOT NULL,
      receipt_hash VARCHAR(255) DEFAULT NULL,
      vote_type ENUM('yes','no') DEFAULT 'yes',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE,
      FOREIGN KEY (position_id) REFERENCES positions(id) ON DELETE CASCADE,
      FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
    )`);

    await db.query(`CREATE TABLE audit_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      admin_id INT,
      admin_code VARCHAR(10),
      action VARCHAR(100) NOT NULL,
      details TEXT,
      ip_address VARCHAR(45),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.query(`CREATE TABLE announcements (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      content TEXT,
      is_active TINYINT(1) DEFAULT 1,
      priority ENUM('low','medium','high') DEFAULT 'medium',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.query(`CREATE TABLE voter_election_access (
      id INT AUTO_INCREMENT PRIMARY KEY,
      voter_id INT NOT NULL,
      election_id INT NOT NULL,
      FOREIGN KEY (voter_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE,
      UNIQUE KEY unique_access (voter_id, election_id)
    )`);

    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminPassword) {
      return;
    }
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const adminCode = generateCode(8);
    await db.query(
      'INSERT INTO users (code, password, role) VALUES (?, ?, ?)',
      [adminCode, hashedPassword, 'admin']
    );
  } catch (err) {
    console.error('Auto-setup error:', err.message);
  }
}

async function migrateDB() {
  async function addColumn(table, column, definition) {
    try {
      if (!SAFE_TABLES.includes(table)) throw new Error('Invalid table');
      if (!SAFE_COLUMNS[table] || !SAFE_COLUMNS[table].includes(column)) throw new Error('Invalid column');
      const validDef = definition.replace(/[^A-Za-z0-9_(),\s'".\\-]/g, '');
      const [cols] = await db.query(`SHOW COLUMNS FROM \`${table}\` LIKE ?`, [column]);
      if (cols.length === 0) {
        await db.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${validDef}`);
      }
    } catch (e) { /* skip */ }
  }

  await addColumn('users', 'password', "VARCHAR(255) DEFAULT NULL");
  await addColumn('users', 'totp_secret', "VARCHAR(255) DEFAULT NULL");
  await addColumn('users', 'totp_enabled', "TINYINT(1) DEFAULT 0");
  await addColumn('users', 'pin', "VARCHAR(255) DEFAULT NULL");
  await addColumn('users', 'email', "VARCHAR(255) DEFAULT NULL");
  await addColumn('elections', 'logo_url', "VARCHAR(500) DEFAULT NULL");
  await addColumn('elections', 'primary_color', "VARCHAR(7) DEFAULT NULL");
  await addColumn('elections', 'secondary_color', "VARCHAR(7) DEFAULT NULL");
  await addColumn('elections', 'results_published', "TINYINT(1) DEFAULT 0");
  await addColumn('candidates', 'sort_order', "INT DEFAULT 0");
  await addColumn('votes', 'receipt_hash', "VARCHAR(255) DEFAULT NULL");
  await addColumn('votes', 'vote_type', "ENUM('yes','no') DEFAULT 'yes'");

  try {
    await db.query(`CREATE TABLE IF NOT EXISTS audit_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      admin_id INT,
      admin_code VARCHAR(10),
      action VARCHAR(100) NOT NULL,
      details TEXT,
      ip_address VARCHAR(45),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
  } catch (e) { /* table exists */ }
  try {
    await db.query(`CREATE TABLE IF NOT EXISTS announcements (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      content TEXT,
      is_active TINYINT(1) DEFAULT 1,
      priority ENUM('low','medium','high') DEFAULT 'medium',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
  } catch (e) { /* table exists */ }
  try {
    await db.query(`CREATE TABLE IF NOT EXISTS voter_election_access (
      id INT AUTO_INCREMENT PRIMARY KEY,
      voter_id INT NOT NULL,
      election_id INT NOT NULL,
      FOREIGN KEY (voter_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE,
      UNIQUE KEY unique_access (voter_id, election_id)
    )`);
  } catch (e) { /* table exists */ }
}

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https' && !req.path.startsWith('/api/')) {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

const sessionStore = new MySQLStore({
  clearExpired: true,
  checkExpirationInterval: 900000,
  expiration: 24 * 60 * 60 * 1000,
  createDatabaseTable: true,
  schema: { tableName: 'sessions' }
}, db);

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  name: 'connect.sid',
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: 'auto',
    sameSite: 'strict'
  }
}));

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get('/api/csrf-token', (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = generateCSRFToken();
  res.cookie('csrf-token', req.session.csrfToken, {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  });
  res.json({ token: req.session.csrfToken });
});

app.use('/api/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/auth/admin/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many admin login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/votes/cast', rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many vote attempts. Please wait.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/votes/results', rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many requests. Please wait.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/votes/verify-receipt', rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many requests. Please wait.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/auth/admin/2fa-verify', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: { error: 'Too many 2FA attempts. Try again in 5 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/auth/voter/set-pin', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many PIN change attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/auth/admin/2fa-enable', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many 2FA setup attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self' ws: wss:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; '));
  next();
});

function csrfProtect(req, res, next) {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const headerToken = req.headers['x-csrf-token'];
    const cookieToken = req.cookies && req.cookies['csrf-token'];
    const bodyToken = req.body?.csrfToken;
    const token = headerToken || cookieToken || bodyToken;
    if (!token || token !== req.session.csrfToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  next();
}

app.use('/api', csrfProtect);

app.use('/api/auth', require('./routes/auth'));
app.use('/api/votes', require('./routes/votes'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/announcements', require('./routes/announcements'));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views/index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views/login.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'views/admin-login.html')));
app.get('/admin/2fa-setup', (req, res) => res.sendFile(path.join(__dirname, 'views/admin-2fa.html')));
app.get('/ballot', (req, res) => res.sendFile(path.join(__dirname, 'views/ballot.html')));
app.get('/results', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'views/results.html'));
});
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'views/admin.html')));

server.listen(PORT, () => {
  autoSetup();
});
