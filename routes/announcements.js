const express = require('express');
const router = express.Router();
const db = require('../config/db');

const adminAuth = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

router.get('/active', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM announcements WHERE is_active = 1 ORDER BY priority DESC, created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/', adminAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM announcements ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/', adminAuth, async (req, res) => {
  try {
    const { title, content, priority } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const [result] = await db.query(
      'INSERT INTO announcements (title, content, priority) VALUES (?, ?, ?)',
      [title, content || null, priority || 'medium']
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.put('/:id', adminAuth, async (req, res) => {
  try {
    const { title, content, is_active, priority } = req.body;
    await db.query(
      'UPDATE announcements SET title = COALESCE(?, title), content = COALESCE(?, content), is_active = COALESCE(?, is_active), priority = COALESCE(?, priority) WHERE id = ?',
      [title, content, is_active, priority, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.delete('/:id', adminAuth, async (req, res) => {
  try {
    await db.query('DELETE FROM announcements WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
