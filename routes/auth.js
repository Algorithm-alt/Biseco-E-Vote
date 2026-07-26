const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const db = require('../config/db');
const { sanitizeInput } = require('../utils');

const failedLoginAttempts = new Map();
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_WINDOW = 15 * 60 * 1000;

function isLockedOut(identifier) {
  const record = failedLoginAttempts.get(identifier);
  if (!record) return false;
  if (Date.now() - record.firstAttempt > LOCKOUT_WINDOW) {
    failedLoginAttempts.delete(identifier);
    return false;
  }
  return record.count >= LOCKOUT_THRESHOLD;
}

function recordFailedAttempt(identifier) {
  const record = failedLoginAttempts.get(identifier);
  if (!record || Date.now() - record.firstAttempt > LOCKOUT_WINDOW) {
    failedLoginAttempts.set(identifier, { count: 1, firstAttempt: Date.now() });
  } else {
    record.count++;
  }
}

function clearFailedAttempts(identifier) {
  failedLoginAttempts.delete(identifier);
}

router.post('/login', async (req, res) => {
  try {
    const { code, pin } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required' });

    const trimmedCode = sanitizeInput(code, 10);
    if (!trimmedCode) return res.status(400).json({ error: 'Invalid code format' });

    if (isLockedOut('voter:' + trimmedCode)) {
      return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
    }

    const [rows] = await db.query('SELECT * FROM users WHERE code = ?', [trimmedCode]);
    if (rows.length === 0) {
      recordFailedAttempt('voter:' + trimmedCode);
      return res.status(401).json({ error: 'Invalid code' });
    }

    const user = rows[0];
    if (user.role === 'voter' && user.has_voted) {
      return res.status(403).json({ error: 'This code has already been used to vote' });
    }

    if (user.pin) {
      if (!pin) {
        return res.status(400).json({ error: 'PIN is required' });
      }
      const pinMatch = await bcrypt.compare(pin, user.pin);
      if (!pinMatch) {
        recordFailedAttempt('voter:' + trimmedCode);
        return res.status(401).json({ error: 'Invalid PIN' });
      }
    }

    clearFailedAttempts('voter:' + trimmedCode);

    const oldSessionId = req.session.id;
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: 'Internal server error' });
      }
      req.session.user = { id: user.id, code: user.code, role: user.role, has_voted: user.has_voted };
      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({ error: 'Internal server error' });
        }
        res.json({ success: true, user: req.session.user });
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/admin/login', async (req, res) => {
  try {
    const { code, password } = req.body;
    if (!code || !password) return res.status(400).json({ error: 'Code and password are required' });

    const trimmedCode = sanitizeInput(code, 10);
    if (!trimmedCode) return res.status(400).json({ error: 'Invalid code format' });

    if (isLockedOut('admin:' + trimmedCode)) {
      return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
    }

    const [rows] = await db.query('SELECT * FROM users WHERE code = ? AND role = "admin"', [trimmedCode]);
    if (rows.length === 0) {
      recordFailedAttempt('admin:' + trimmedCode);
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const user = rows[0];

    if (!user.password) {
      return res.status(401).json({ error: 'Admin account not properly configured.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      recordFailedAttempt('admin:' + trimmedCode);
      return res.status(401).json({ error: 'Invalid password' });
    }

    clearFailedAttempts('admin:' + trimmedCode);

    if (user.totp_enabled) {
      req.session.pendingAdmin = { id: user.id, code: user.code };
      return res.json({ success: true, requires2FA: true });
    }

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      req.session.user = { id: user.id, code: user.code, role: 'admin', totp_enabled: user.totp_enabled };
      db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
        [user.id, user.code, 'admin_login', req.ip]).catch(() => {});
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Internal server error' });
        res.json({ success: true, user: req.session.user });
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/admin/2fa-verify', async (req, res) => {
  try {
    if (!req.session.pendingAdmin) return res.status(400).json({ error: 'No pending 2FA verification' });

    const { token } = req.body;
    if (!token) return res.status(400).json({ error: '2FA token required' });

    const tokenStr = sanitizeInput(String(token), 10);
    if (!tokenStr) return res.status(400).json({ error: 'Invalid token format' });

    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.session.pendingAdmin.id]);
    if (rows.length === 0) return res.status(401).json({ error: 'User not found' });

    const user = rows[0];
    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: tokenStr,
      window: 1
    });

    if (!verified) return res.status(401).json({ error: 'Invalid 2FA token' });

    const pendingId = req.session.pendingAdmin.id;
    const pendingCode = req.session.pendingAdmin.code;

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      req.session.user = { id: pendingId, code: pendingCode, role: 'admin', totp_enabled: user.totp_enabled };
      db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
        [pendingId, pendingCode, 'admin_login_2fa', req.ip]).catch(() => {});
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: 'Internal server error' });
        res.json({ success: true, user: req.session.user });
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/admin/2fa-setup', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const secret = speakeasy.generateSecret({
      name: 'BISECO Election (' + req.session.user.code + ')',
      issuer: 'BISECO E-Vote'
    });

    req.session.pendingTotpSecret = secret.base32;

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ success: true, qrCode: qrCodeUrl });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/admin/2fa-enable', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    if (!req.session.pendingTotpSecret) {
      return res.status(400).json({ error: 'No pending 2FA setup. Run setup first.' });
    }

    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });

    const tokenStr = sanitizeInput(String(token), 10);
    if (!tokenStr) return res.status(400).json({ error: 'Invalid token format' });

    const verified = speakeasy.totp.verify({
      secret: req.session.pendingTotpSecret,
      encoding: 'base32',
      token: tokenStr,
      window: 1
    });

    if (!verified) return res.status(400).json({ error: 'Invalid token. Please try again.' });

    await db.query('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?',
      [req.session.pendingTotpSecret, req.session.user.id]);
    req.session.user.totp_enabled = 1;
    delete req.session.pendingTotpSecret;

    db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
      [req.session.user.id, req.session.user.code, '2fa_enabled', req.ip]).catch(() => {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/admin/2fa-disable', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

    const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [req.session.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (rows[0].password) {
      const match = await bcrypt.compare(password, rows[0].password);
      if (!match) return res.status(401).json({ error: 'Invalid password' });
    }

    await db.query('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [req.session.user.id]);
    req.session.user.totp_enabled = 0;

    db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
      [req.session.user.id, req.session.user.code, '2fa_disabled', req.ip]).catch(() => {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/admin/change-password', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (newPassword.length > 128) return res.status(400).json({ error: 'Password too long' });
    if (newPassword === currentPassword) return res.status(400).json({ error: 'New password must differ from current' });

    const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [req.session.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (rows[0].password) {
      const match = await bcrypt.compare(currentPassword, rows[0].password);
      if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
    } else {
      return res.status(401).json({ error: 'Admin account not properly configured.' });
    }

    const hashed = await bcrypt.hash(newPassword, 12);
    await db.query('UPDATE users SET password = ? WHERE id = ?', [hashed, req.session.user.id]);

    const userId = req.session.user.id;
    const userCode = req.session.user.code;
    const userIp = req.ip;
    req.session.destroy((err) => {
      if (err) { /* continue */ }
      db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
        [userId, userCode, 'password_changed', userIp]).catch(() => {});
      res.json({ success: true, message: 'Password changed. Please login again.' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/voter/set-pin', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'voter') {
      return res.status(403).json({ error: 'Voter access required' });
    }

    const { pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'PIN is required' });
    if (pin.length < 4 || pin.length > 8) return res.status(400).json({ error: 'PIN must be 4-8 digits' });
    if (!/^\d+$/.test(pin)) return res.status(400).json({ error: 'PIN must contain only digits' });

    const hashedPin = await bcrypt.hash(pin, 10);
    await db.query('UPDATE users SET pin = ? WHERE id = ?', [hashedPin, req.session.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

router.get('/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.session.user);
});

module.exports = router;
