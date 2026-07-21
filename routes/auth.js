const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const db = require('../config/db');

router.post('/login', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required' });

    const trimmedCode = code.trim();
    const [rows] = await db.query('SELECT * FROM users WHERE code = ?', [trimmedCode]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid code' });

    const user = rows[0];
    if (user.role === 'voter' && user.has_voted) {
      return res.status(403).json({ error: 'This code has already been used to vote' });
    }

    req.session.user = { id: user.id, code: user.code, role: user.role, has_voted: user.has_voted };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/admin/login', async (req, res) => {
  try {
    const { code, password } = req.body;
    if (!code || !password) return res.status(400).json({ error: 'Code and password are required' });

    const [rows] = await db.query('SELECT * FROM users WHERE code = ? AND role = "admin"', [code.trim()]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid admin credentials' });

    const user = rows[0];

    if (!user.password) {
      const match = password === 'admin123';
      if (!match) return res.status(401).json({ error: 'Invalid password' });
    } else {
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ error: 'Invalid password' });
    }

    if (user.totp_enabled) {
      req.session.pendingAdmin = { id: user.id, code: user.code };
      return res.json({ success: true, requires2FA: true });
    }

    req.session.user = { id: user.id, code: user.code, role: 'admin', totp_enabled: user.totp_enabled };
    await db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
      [user.id, user.code, 'admin_login', req.ip]);
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/admin/2fa-verify', async (req, res) => {
  try {
    if (!req.session.pendingAdmin) return res.status(400).json({ error: 'No pending 2FA verification' });

    const { token } = req.body;
    if (!token) return res.status(400).json({ error: '2FA token required' });

    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.session.pendingAdmin.id]);
    if (rows.length === 0) return res.status(401).json({ error: 'User not found' });

    const user = rows[0];
    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: token,
      window: 2
    });

    if (!verified) return res.status(401).json({ error: 'Invalid 2FA token' });

    req.session.user = { id: user.id, code: user.code, role: 'admin', totp_enabled: user.totp_enabled };
    delete req.session.pendingAdmin;

    await db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
      [user.id, user.code, 'admin_login_2fa', req.ip]);
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    res.status(500).json({ error: err.message });
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

    await db.query('UPDATE users SET totp_secret = ? WHERE id = ?', [secret.base32, req.session.user.id]);

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ success: true, secret: secret.base32, qrCode: qrCodeUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/admin/2fa-enable', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { token } = req.body;
    const [rows] = await db.query('SELECT totp_secret FROM users WHERE id = ?', [req.session.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const verified = speakeasy.totp.verify({
      secret: rows[0].totp_secret,
      encoding: 'base32',
      token: token,
      window: 2
    });

    if (!verified) return res.status(400).json({ error: 'Invalid token. Please try again.' });

    await db.query('UPDATE users SET totp_enabled = 1 WHERE id = ?', [req.session.user.id]);
    req.session.user.totp_enabled = 1;

    await db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
      [req.session.user.id, req.session.user.code, '2fa_enabled', req.ip]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/admin/2fa-disable', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { password } = req.body;
    const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [req.session.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (rows[0].password) {
      const match = await bcrypt.compare(password, rows[0].password);
      if (!match) return res.status(401).json({ error: 'Invalid password' });
    }

    await db.query('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [req.session.user.id]);
    req.session.user.totp_enabled = 0;

    await db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
      [req.session.user.id, req.session.user.code, '2fa_disabled', req.ip]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/admin/change-password', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [req.session.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (rows[0].password) {
      const match = await bcrypt.compare(currentPassword, rows[0].password);
      if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
    } else {
      if (currentPassword !== 'admin123') return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password = ? WHERE id = ?', [hashed, req.session.user.id]);

    await db.query('INSERT INTO audit_logs (admin_id, admin_code, action, ip_address) VALUES (?, ?, ?, ?)',
      [req.session.user.id, req.session.user.code, 'password_changed', req.ip]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

router.get('/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.session.user);
});

module.exports = router;
