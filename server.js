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
const { autoSetup } = require('./config/migrate');

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
  wsClients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) client.send(msg);
  });
}
app.set('broadcastVoteUpdate', broadcastVoteUpdate);

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === 'production' &&
    req.headers['x-forwarded-proto'] &&
    req.headers['x-forwarded-proto'] !== 'https' &&
    !req.path.startsWith('/api/')
  ) {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

const sessionStore = new MySQLStore(
  {
    clearExpired: true,
    checkExpirationInterval: 900000,
    expiration: 24 * 60 * 60 * 1000,
    createDatabaseTable: true,
    schema: { tableName: 'sessions' },
  },
  db
);

app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    name: 'connect.sid',
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: 'auto',
      sameSite: 'strict',
    },
  })
);

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
    maxAge: 24 * 60 * 60 * 1000,
  });
  res.json({ token: req.session.csrfToken });
});

app.use(
  '/api/auth/login',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts. Try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/auth/admin/login',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many admin login attempts. Try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/votes/cast',
  rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Too many vote attempts. Please wait.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/votes/results',
  rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: 'Too many requests. Please wait.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/auth/admin/2fa-verify',
  rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5,
    message: { error: 'Too many 2FA attempts. Try again in 5 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/auth/voter/set-pin',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many PIN change attempts. Try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/auth/admin/2fa-enable',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many 2FA setup attempts. Try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/auth/admin/forgot-password',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many reset requests. Try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  '/api/auth/admin/reset-password',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many reset attempts. Try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self'",
      "connect-src 'self' ws: wss:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  );
  next();
});

function csrfProtect(req, res, next) {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const headerToken = req.headers['x-csrf-token'];
    const bodyToken = req.body?.csrfToken;
    const token = headerToken || bodyToken;
    if (!token || token !== req.session.csrfToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  next();
}

app.use('/api/auth', require('./routes/auth'));
app.use('/api/votes', require('./routes/votes'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/announcements', require('./routes/announcements'));

app.post('/api/setup', async (req, res) => {
  try {
    const { autoSetup } = require('./config/migrate');
    await autoSetup();
    res.json({ success: true, message: 'Database setup completed' });
  } catch (err) {
    console.error('Manual setup failed:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.use('/api', csrfProtect);

app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'unhealthy', error: err.message });
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views/index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views/login.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'views/admin-login.html')));
app.get('/admin/forgot-password', (req, res) =>
  res.sendFile(path.join(__dirname, 'views/admin-forgot.html'))
);
app.get('/admin/reset-password', (req, res) =>
  res.sendFile(path.join(__dirname, 'views/admin-reset.html'))
);
app.get('/admin/2fa-setup', (req, res) =>
  res.sendFile(path.join(__dirname, 'views/admin-2fa.html'))
);
app.get('/ballot', (req, res) => res.sendFile(path.join(__dirname, 'views/ballot.html')));
app.get('/results', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'views/results.html'));
});
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'views/admin.html')));

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  autoSetup().catch((err) => console.error('autoSetup failed:', err));
});
