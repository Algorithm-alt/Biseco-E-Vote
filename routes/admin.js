const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../config/db');
const multer = require('multer');
const path = require('path');
const { generateCode, sanitizeInput, isValidUrl } = require('../utils');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '..', 'public', 'uploads')),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, 'candidate-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExts = ['.jpeg', '.jpg', '.png', '.gif', '.webp'];
    if (allowedExts.includes(ext) && allowedMimes.includes(file.mimetype)) return cb(null, true);
    cb(new Error('Only image files allowed'));
  },
});

const adminAuth = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

async function logAudit(adminId, adminCode, action, details, ip) {
  try {
    await db.query(
      'INSERT INTO audit_logs (admin_id, admin_code, action, details, ip_address) VALUES (?, ?, ?, ?, ?)',
      [adminId, adminCode, action, (details || '').substring(0, 1000), ip || null]
    );
  } catch (e) {
    /* silent */
  }
}

router.get('/stats', adminAuth, async (req, res) => {
  try {
    const [voters] = await db.query("SELECT COUNT(*) as count FROM users WHERE role = 'voter'");
    const [voted] = await db.query('SELECT COUNT(DISTINCT voter_hash) as count FROM votes');
    const [elections] = await db.query('SELECT COUNT(*) as count FROM elections');
    const [activeElections] = await db.query(
      "SELECT COUNT(*) as count FROM elections WHERE status = 'active'"
    );
    const [positions] = await db.query('SELECT COUNT(*) as count FROM positions');
    const [candidates] = await db.query(
      "SELECT COUNT(*) as count FROM candidates c JOIN positions p ON c.position_id = p.id JOIN elections e ON p.election_id = e.id WHERE e.status = 'active'"
    );
    const [totalVotes] = await db.query('SELECT COUNT(*) as count FROM votes');
    res.json({
      voters: voters[0].count,
      voted: voted[0].count,
      turnout: voters[0].count > 0 ? Math.round((voted[0].count / voters[0].count) * 100) : 0,
      elections: elections[0].count,
      active_elections: activeElections[0].count,
      positions: positions[0].count,
      candidates: candidates[0].count,
      total_votes: totalVotes[0].count,
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/generate-codes', adminAuth, async (req, res) => {
  try {
    const { count } = req.body;
    if (!count || count < 1 || count > 1000)
      return res.status(400).json({ error: 'Enter a number between 1 and 1000' });
    const codes = [];
    for (let i = 0; i < count; i++) {
      let code,
        unique = false;
      while (!unique) {
        code = generateCode(8);
        const [exists] = await db.query('SELECT id FROM users WHERE code = ?', [code]);
        if (exists.length === 0) unique = true;
      }
      await db.query('INSERT INTO users (code, role) VALUES (?, ?)', [code, 'voter']);
      codes.push(code);
    }
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'generate_codes',
      `Generated ${count} codes`,
      req.ip
    );
    res.json({ success: true, count: codes.length, codes });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/bulk-import-codes', adminAuth, async (req, res) => {
  try {
    const csvData = (req.body.csvData || '').toString().trim();
    if (!csvData) return res.status(400).json({ error: 'CSV data required' });
    const lines = csvData.split(/\r?\n/).filter((l) => l.trim());
    if (lines.length > 5000)
      return res.status(400).json({ error: 'Maximum 5000 codes per import' });
    const codes = [];
    for (const line of lines) {
      const trimmed = sanitizeInput(line, 10);
      if (!trimmed) continue;
      if (!/^[A-Za-z0-9]+$/.test(trimmed)) continue;
      const [exists] = await db.query('SELECT id FROM users WHERE code = ?', [trimmed]);
      if (exists.length === 0) {
        await db.query('INSERT INTO users (code, role) VALUES (?, ?)', [trimmed, 'voter']);
        codes.push(trimmed);
      }
    }
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'bulk_import',
      `Imported ${codes.length} codes from CSV`,
      req.ip
    );
    res.json({ success: true, count: codes.length, codes });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/elections', adminAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM elections ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/elections', adminAuth, async (req, res) => {
  try {
    const { name, description, start_date, end_date, logo_url, primary_color, secondary_color } =
      req.body;
    const sanitizedName = sanitizeInput(name, 200);
    if (!sanitizedName) return res.status(400).json({ error: 'Election name is required' });
    const sanitizedDesc = sanitizeInput(description, 2000);
    const sanitizedLogo = logo_url
      ? isValidUrl(logo_url)
        ? sanitizeInput(logo_url, 500)
        : null
      : null;
    const sanitizedPrimary = primary_color ? sanitizeInput(primary_color, 7) : null;
    const sanitizedSecondary = secondary_color ? sanitizeInput(secondary_color, 7) : null;

    const [result] = await db.query(
      'INSERT INTO elections (name, description, start_date, end_date, logo_url, primary_color, secondary_color) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        sanitizedName,
        sanitizedDesc,
        start_date || null,
        end_date || null,
        sanitizedLogo,
        sanitizedPrimary,
        sanitizedSecondary,
      ]
    );
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'create_election',
      `Created election: ${sanitizedName}`,
      req.ip
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/elections/:id', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.id);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const { name, description, start_date, end_date, logo_url, primary_color, secondary_color } =
      req.body;
    const sanitizedName = name ? sanitizeInput(name, 200) : null;
    const sanitizedDesc = description ? sanitizeInput(description, 2000) : null;
    const sanitizedLogo = logo_url
      ? isValidUrl(logo_url)
        ? sanitizeInput(logo_url, 500)
        : null
      : null;
    const sanitizedPrimary = primary_color ? sanitizeInput(primary_color, 7) : null;
    const sanitizedSecondary = secondary_color ? sanitizeInput(secondary_color, 7) : null;

    await db.query(
      'UPDATE elections SET name = COALESCE(?, name), description = COALESCE(?, description), start_date = COALESCE(?, start_date), end_date = COALESCE(?, end_date), logo_url = COALESCE(?, logo_url), primary_color = COALESCE(?, primary_color), secondary_color = COALESCE(?, secondary_color) WHERE id = ?',
      [
        sanitizedName,
        sanitizedDesc,
        start_date,
        end_date,
        sanitizedLogo,
        sanitizedPrimary,
        sanitizedSecondary,
        electionId,
      ]
    );
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'update_election',
      `Updated election #${electionId}`,
      req.ip
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/elections/:id/status', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.id);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const { status } = req.body;
    if (!['upcoming', 'active', 'closed'].includes(status))
      return res.status(400).json({ error: 'Invalid status' });
    if (status === 'active') await db.query("UPDATE elections SET status = 'upcoming'");
    await db.query('UPDATE elections SET status = ? WHERE id = ?', [status, electionId]);
    const [el] = await db.query('SELECT name FROM elections WHERE id = ?', [electionId]);
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'election_status',
      `Set "${el[0]?.name}" to ${status}`,
      req.ip
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/elections/:id/results', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.id);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const { results_published } = req.body;
    if (typeof results_published !== 'boolean')
      return res.status(400).json({ error: 'results_published must be boolean' });
    await db.query('UPDATE elections SET results_published = ? WHERE id = ?', [
      results_published ? 1 : 0,
      electionId,
    ]);
    const [el] = await db.query('SELECT name FROM elections WHERE id = ?', [electionId]);
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'results_toggle',
      `${results_published ? 'Published' : 'Unpublished'} results for "${el[0]?.name}"`,
      req.ip
    );
    res.json({ success: true, results_published });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/elections/:id', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.id);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [el] = await db.query('SELECT name FROM elections WHERE id = ?', [electionId]);
    await db.query('DELETE FROM elections WHERE id = ?', [electionId]);
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'delete_election',
      `Deleted election: ${el[0]?.name}`,
      req.ip
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/elections/:id/clone', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.id);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [el] = await db.query('SELECT * FROM elections WHERE id = ?', [electionId]);
    if (el.length === 0) return res.status(404).json({ error: 'Election not found' });
    const orig = el[0];
    const [newEl] = await db.query(
      'INSERT INTO elections (name, description, start_date, end_date, logo_url, primary_color, secondary_color) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        (orig.name || '').substring(0, 190) + ' (Copy)',
        orig.description,
        orig.start_date,
        orig.end_date,
        orig.logo_url,
        orig.primary_color,
        orig.secondary_color,
      ]
    );
    const newElectionId = newEl.insertId;
    const [positions] = await db.query('SELECT * FROM positions WHERE election_id = ?', [
      electionId,
    ]);
    for (const pos of positions) {
      await db.query(
        'INSERT INTO positions (election_id, name, description, sort_order) VALUES (?, ?, ?, ?)',
        [newElectionId, pos.name, pos.description, pos.sort_order]
      );
    }
    await logAudit(
      req.session.user.id,
      req.session.user.code,
      'clone_election',
      `Cloned election #${electionId} to #${newElectionId}`,
      req.ip
    );
    res.json({ success: true, id: newElectionId });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/positions/:electionId', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.electionId);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [rows] = await db.query(
      'SELECT p.*, (SELECT COUNT(*) FROM candidates WHERE position_id = p.id) as candidate_count FROM positions p WHERE p.election_id = ? ORDER BY p.sort_order, p.id',
      [electionId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/positions', adminAuth, async (req, res) => {
  try {
    const { election_id, name, description, sort_order } = req.body;
    const electionIdInt = parseInt(election_id);
    const sanitizedName = sanitizeInput(name, 100);
    if (isNaN(electionIdInt) || !sanitizedName)
      return res.status(400).json({ error: 'Election and name are required' });
    const sanitizedDesc = sanitizeInput(description, 2000);

    const [result] = await db.query(
      'INSERT INTO positions (election_id, name, description, sort_order) VALUES (?, ?, ?, ?)',
      [electionIdInt, sanitizedName, sanitizedDesc, parseInt(sort_order) || 0]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/positions/reorder', adminAuth, async (req, res) => {
  try {
    const { order } = req.body;
    if (!Array.isArray(order)) return res.status(400).json({ error: 'Order array required' });
    for (const item of order) {
      const itemId = parseInt(item.id);
      const itemOrder = parseInt(item.sort_order);
      if (!isNaN(itemId) && !isNaN(itemOrder)) {
        await db.query('UPDATE positions SET sort_order = ? WHERE id = ?', [itemOrder, itemId]);
      }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/positions/:id', adminAuth, async (req, res) => {
  try {
    const posId = parseInt(req.params.id);
    if (isNaN(posId)) return res.status(400).json({ error: 'Invalid position ID' });

    const { name, description, sort_order } = req.body;
    const sanitizedName = name ? sanitizeInput(name, 100) : null;
    const sanitizedDesc = description !== undefined ? sanitizeInput(description, 2000) : null;

    await db.query(
      'UPDATE positions SET name = COALESCE(?, name), description = COALESCE(?, description), sort_order = COALESCE(?, sort_order) WHERE id = ?',
      [
        sanitizedName,
        sanitizedDesc,
        sort_order !== undefined && sort_order !== null ? parseInt(sort_order) : null,
        posId,
      ]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/positions/:id', adminAuth, async (req, res) => {
  try {
    const posId = parseInt(req.params.id);
    if (isNaN(posId)) return res.status(400).json({ error: 'Invalid position ID' });
    await db.query('DELETE FROM positions WHERE id = ?', [posId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/candidates/:positionId', adminAuth, async (req, res) => {
  try {
    const posId = parseInt(req.params.positionId);
    if (isNaN(posId)) return res.status(400).json({ error: 'Invalid position ID' });
    const [rows] = await db.query(
      'SELECT * FROM candidates WHERE position_id = ? ORDER BY sort_order, id',
      [posId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/all-candidates/:electionId', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.electionId);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [rows] = await db.query(
      `SELECT c.*, p.name as position_name FROM candidates c JOIN positions p ON c.position_id = p.id WHERE p.election_id = ? ORDER BY p.sort_order, c.sort_order, c.id`,
      [electionId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/candidates', adminAuth, upload.single('photo'), async (req, res) => {
  try {
    const { position_id, name, manifesto } = req.body;
    const posId = parseInt(position_id);
    const sanitizedName = sanitizeInput(name, 100);
    if (isNaN(posId) || !sanitizedName)
      return res.status(400).json({ error: 'Position and name are required' });
    const sanitizedManifesto = sanitizeInput(manifesto, 5000);
    const photo = req.file ? '/uploads/' + req.file.filename : '/images/placeholder.png';

    const [result] = await db.query(
      'INSERT INTO candidates (position_id, name, photo, manifesto) VALUES (?, ?, ?, ?)',
      [posId, sanitizedName, photo, sanitizedManifesto]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/candidates/reorder', adminAuth, async (req, res) => {
  try {
    const { order } = req.body;
    if (!Array.isArray(order)) return res.status(400).json({ error: 'Order array required' });
    for (const item of order) {
      const itemId = parseInt(item.id);
      const itemOrder = parseInt(item.sort_order);
      if (!isNaN(itemId) && !isNaN(itemOrder)) {
        await db.query('UPDATE candidates SET sort_order = ? WHERE id = ?', [itemOrder, itemId]);
      }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/candidates/:id', adminAuth, upload.single('photo'), async (req, res) => {
  try {
    const candId = parseInt(req.params.id);
    if (isNaN(candId)) return res.status(400).json({ error: 'Invalid candidate ID' });

    const { name, manifesto } = req.body;
    const sanitizedName = name ? sanitizeInput(name, 100) : null;
    const sanitizedManifesto = manifesto !== undefined ? sanitizeInput(manifesto, 5000) : null;

    if (req.file) {
      await db.query(
        'UPDATE candidates SET name = COALESCE(?, name), photo = ?, manifesto = COALESCE(?, manifesto) WHERE id = ?',
        [sanitizedName, '/uploads/' + req.file.filename, sanitizedManifesto, candId]
      );
    } else {
      await db.query(
        'UPDATE candidates SET name = COALESCE(?, name), manifesto = COALESCE(?, manifesto) WHERE id = ?',
        [sanitizedName, sanitizedManifesto, candId]
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/candidates/:id', adminAuth, async (req, res) => {
  try {
    const candId = parseInt(req.params.id);
    if (isNaN(candId)) return res.status(400).json({ error: 'Invalid candidate ID' });
    await db.query('DELETE FROM candidates WHERE id = ?', [candId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/voters', adminAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, code, has_voted, created_at FROM users WHERE role = 'voter' ORDER BY created_at DESC"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/voters/:id', adminAuth, async (req, res) => {
  try {
    const voterId = parseInt(req.params.id);
    if (isNaN(voterId)) return res.status(400).json({ error: 'Invalid voter ID' });
    await db.query('DELETE FROM users WHERE id = ? AND role = ?', [voterId, 'voter']);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/voters-all', adminAuth, async (req, res) => {
  try {
    await db.query('DELETE FROM users WHERE role = ?', ['voter']);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/voters/:id/access', adminAuth, async (req, res) => {
  try {
    const voterId = parseInt(req.params.id);
    if (isNaN(voterId)) return res.status(400).json({ error: 'Invalid voter ID' });
    const [rows] = await db.query(
      'SELECT election_id FROM voter_election_access WHERE voter_id = ?',
      [voterId]
    );
    res.json(rows.map((r) => r.election_id));
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/voters/:id/access', adminAuth, async (req, res) => {
  try {
    const voterId = parseInt(req.params.id);
    if (isNaN(voterId)) return res.status(400).json({ error: 'Invalid voter ID' });

    const { election_ids } = req.body;
    await db.query('DELETE FROM voter_election_access WHERE voter_id = ?', [voterId]);
    if (election_ids && Array.isArray(election_ids) && election_ids.length > 0) {
      for (const elId of election_ids) {
        const elIdInt = parseInt(elId);
        if (!isNaN(elIdInt)) {
          await db.query(
            'INSERT IGNORE INTO voter_election_access (voter_id, election_id) VALUES (?, ?)',
            [voterId, elIdInt]
          );
        }
      }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/vote-turnout/:electionId', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.electionId);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [rows] = await db.query(
      `SELECT DISTINCT v.voter_hash as code, v.created_at as voted_at
       FROM votes v WHERE v.election_id = ?
       ORDER BY v.created_at DESC`,
      [electionId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/export-results/:electionId', adminAuth, async (req, res) => {
  try {
    const electionId = parseInt(req.params.electionId);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [election] = await db.query('SELECT * FROM elections WHERE id = ?', [electionId]);
    if (election.length === 0) return res.status(404).json({ error: 'Election not found' });
    const [positions] = await db.query(
      'SELECT * FROM positions WHERE election_id = ? ORDER BY sort_order, id',
      [electionId]
    );
    const results = [];
    for (const pos of positions) {
      const [candidates] = await db.query(
        `SELECT c.id, c.name, COUNT(v.id) as vote_count FROM candidates c LEFT JOIN votes v ON c.id = v.candidate_id AND v.election_id = ? WHERE c.position_id = ? GROUP BY c.id ORDER BY vote_count DESC`,
        [electionId, pos.id]
      );
      results.push({ position: pos.name, candidates });
    }
    const header = ['Position', 'Candidate', 'Votes'];
    const rows = [];
    for (const pos of results) {
      for (const c of pos.candidates) {
        rows.push([pos.position, c.name, c.vote_count]);
      }
    }
    res.json({ election: election[0].name, header, rows });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/profile', adminAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, code, email, totp_enabled, created_at FROM users WHERE id = ?',
      [req.session.user.id]
    );
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/profile', adminAuth, async (req, res) => {
  try {
    const { email } = req.body;
    if (typeof email !== 'string') return res.status(400).json({ error: 'Email is required' });

    const trimmedEmail = sanitizeInput(email, 255);
    if (!trimmedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    await db.query('UPDATE users SET email = ? WHERE id = ?', [trimmedEmail, req.session.user.id]);
    db.query(
      'INSERT INTO audit_logs (admin_id, admin_code, action, details, ip_address) VALUES (?, ?, ?, ?, ?)',
      [req.session.user.id, req.session.user.code, 'email_updated', trimmedEmail, req.ip]
    ).catch(() => {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/audit-logs', adminAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
