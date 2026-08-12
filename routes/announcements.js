const express = require('express');
const router = express.Router();
const db = require('../config/db');
const { sanitizeInput } = require('../utils');

const adminAuth = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

router.get('/active', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM announcements WHERE is_active = 1 ORDER BY priority DESC, created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/', adminAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM announcements ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/', adminAuth, async (req, res) => {
  try {
    const { title, content, priority } = req.body;
    const sanitizedTitle = sanitizeInput(title, 200);
    if (!sanitizedTitle) return res.status(400).json({ error: 'Title required' });
    const sanitizedContent = sanitizeInput(content, 5000);
    const validPriorities = ['low', 'medium', 'high'];
    const sanitizedPriority = validPriorities.includes(priority) ? priority : 'medium';

    const [result] = await db.query(
      'INSERT INTO announcements (title, content, priority) VALUES (?, ?, ?)',
      [sanitizedTitle, sanitizedContent, sanitizedPriority]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/:id', adminAuth, async (req, res) => {
  try {
    const annId = parseInt(req.params.id);
    if (isNaN(annId)) return res.status(400).json({ error: 'Invalid announcement ID' });

    const { title, content, is_active, priority } = req.body;
    const sanitizedTitle = title ? sanitizeInput(title, 200) : null;
    const sanitizedContent = content !== undefined ? sanitizeInput(content, 5000) : null;
    const validPriorities = ['low', 'medium', 'high'];
    const sanitizedPriority = priority && validPriorities.includes(priority) ? priority : null;
    const sanitizedActive = is_active !== undefined ? (is_active ? 1 : 0) : null;

    await db.query(
      'UPDATE announcements SET title = COALESCE(?, title), content = COALESCE(?, content), is_active = COALESCE(?, is_active), priority = COALESCE(?, priority) WHERE id = ?',
      [sanitizedTitle, sanitizedContent, sanitizedActive, sanitizedPriority, annId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const annId = parseInt(req.params.id);
    if (isNaN(annId)) return res.status(400).json({ error: 'Invalid announcement ID' });
    await db.query('DELETE FROM announcements WHERE id = ?', [annId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
