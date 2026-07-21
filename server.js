require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const rateLimit = require('express-rate-limit');
const db = require('./config/db');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 4000;

let wsClients = new Set();
wss.on('connection', (ws) => {
  wsClients.add(ws);
  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

function broadcastVoteUpdate(data) {
  const msg = JSON.stringify(data);
  wsClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) client.send(msg);
  });
}
app.set('broadcastVoteUpdate', broadcastVoteUpdate);

function generateCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let code = '';
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) code += chars[bytes[i] % chars.length];
  return code;
}

function generateReceiptHash() {
  return crypto.randomBytes(16).toString('hex');
}

async function autoSetup() {
  try {
    const [tables] = await db.query("SHOW TABLES LIKE 'users'");
    if (tables.length > 0) {
      const [count] = await db.query('SELECT COUNT(*) as cnt FROM users WHERE role = "admin"');
      if (count[0].cnt > 0) {
        console.log('Database already exists. Migrating if needed...');
        await migrateDB();
        return;
      }
    }

    console.log('Setting up database...');
    await db.query('SET FOREIGN_KEY_CHECKS = 0');
    await db.query('DROP TABLE IF EXISTS votes, candidates, positions, elections, users, audit_logs, announcements, voter_election_access');
    await db.query('SET FOREIGN_KEY_CHECKS = 1');

    await db.query(`CREATE TABLE users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      code VARCHAR(10) NOT NULL UNIQUE,
      password VARCHAR(255) DEFAULT NULL,
      role ENUM('admin','voter') DEFAULT 'voter',
      has_voted TINYINT(1) DEFAULT 0,
      totp_secret VARCHAR(255) DEFAULT NULL,
      totp_enabled TINYINT(1) DEFAULT 0,
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

    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    await db.query(
      'INSERT INTO users (code, password, role) VALUES (?, ?, ?)',
      ['admin123', hashedPassword, 'admin']
    );

    console.log('Database setup complete!');
  } catch (err) {
    console.error('Auto-setup error:', err.message);
  }
}

async function migrateDB() {
  async function addColumn(table, column, definition) {
    try {
      const [cols] = await db.query(`SHOW COLUMNS FROM ${table} LIKE '${column}'`);
      if (cols.length === 0) {
        await db.query(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        console.log(`  Added ${table}.${column}`);
      }
    } catch (e) { /* skip */ }
  }

  await addColumn('users', 'password', "VARCHAR(255) DEFAULT NULL");
  await addColumn('users', 'totp_secret', "VARCHAR(255) DEFAULT NULL");
  await addColumn('users', 'totp_enabled', "TINYINT(1) DEFAULT 0");
  await addColumn('users', 'email', "VARCHAR(255) DEFAULT NULL");
  await addColumn('elections', 'logo_url', "VARCHAR(500) DEFAULT NULL");
  await addColumn('elections', 'primary_color', "VARCHAR(7) DEFAULT NULL");
  await addColumn('elections', 'secondary_color', "VARCHAR(7) DEFAULT NULL");
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
  console.log('Migration complete.');
}

function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'biseco-election-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get('/api/csrf-token', (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = generateCSRFToken();
  res.json({ token: req.session.csrfToken });
});

app.use('/api/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
}));

app.use('/api/admin/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many admin login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
}));

function csrfProtect(req, res, next) {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const token = req.headers['x-csrf-token'] || req.body?.csrfToken;
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
  console.log(`BISECO Vote running at http://localhost:${PORT}`);
  console.log(`WebSocket server ready on ws://localhost:${PORT}`);
  autoSetup();
});
