const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../config/db');
const { generateReceiptHash, sanitizeInput } = require('../utils');

const voterAuth = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'voter') {
    return res.status(403).json({ error: 'Voter access required' });
  }
  next();
};

router.get('/active-election', async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM elections WHERE status = 'active' ORDER BY id DESC LIMIT 1");
    if (rows.length === 0) return res.json(null);
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

router.get('/all-elections', async (req, res) => {
  try {
    const [rows] = await db.query("SELECT id, name, status, start_date, end_date, results_published FROM elections ORDER BY created_at DESC");
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

router.get('/positions/:electionId', async (req, res) => {
  try {
    const electionId = parseInt(req.params.electionId);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [positions] = await db.query(
      'SELECT * FROM positions WHERE election_id = ? ORDER BY sort_order, id',
      [electionId]
    );
    for (const pos of positions) {
      const [candidates] = await db.query(
        'SELECT id, name, photo, manifesto, sort_order FROM candidates WHERE position_id = ? ORDER BY sort_order, id',
        [pos.id]
      );
      pos.candidates = candidates;
    }
    res.json(positions);
  } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

router.get('/candidate/:id', async (req, res) => {
  try {
    const candidateId = parseInt(req.params.id);
    if (isNaN(candidateId)) return res.status(400).json({ error: 'Invalid candidate ID' });

    const [rows] = await db.query(
      `SELECT c.*, p.name as position_name, p.election_id FROM candidates c JOIN positions p ON c.position_id = p.id WHERE c.id = ?`,
      [candidateId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Candidate not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

router.post('/cast', voterAuth, async (req, res) => {
  const connection = await db.getConnection();
  try {
    const { election_id, votes } = req.body;
    if (!election_id || !votes || !Array.isArray(votes)) {
      return res.status(400).json({ error: 'Invalid vote data' });
    }

    const electionIdInt = parseInt(election_id);
    if (isNaN(electionIdInt)) return res.status(400).json({ error: 'Invalid election ID' });

    await connection.beginTransaction();

    const [election] = await connection.query("SELECT * FROM elections WHERE id = ? AND status = 'active' FOR UPDATE", [electionIdInt]);
    if (election.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'No active election found' });
    }

    const [userRows] = await connection.query('SELECT has_voted FROM users WHERE id = ? FOR UPDATE', [req.session.user.id]);
    if (userRows.length === 0 || userRows[0].has_voted) {
      await connection.rollback();
      return res.status(403).json({ error: 'You have already voted in this election' });
    }

    const [accessRows] = await connection.query(
      'SELECT id FROM voter_election_access WHERE voter_id = ? AND election_id = ?',
      [req.session.user.id, electionIdInt]
    );
    const [totalAccess] = await connection.query('SELECT COUNT(*) as cnt FROM voter_election_access WHERE election_id = ?', [electionIdInt]);
    if (totalAccess[0].cnt > 0 && accessRows.length === 0) {
      await connection.rollback();
      return res.status(403).json({ error: 'You are not authorized to vote in this election' });
    }

    const receiptHashes = [];
    for (const vote of votes) {
      if (!vote.position_id || !vote.candidate_id) continue;
      const voteType = (vote.vote_type === 'no') ? 'no' : 'yes';
      const receiptHash = generateReceiptHash();
      await connection.query(
        'INSERT INTO votes (election_id, position_id, candidate_id, voter_hash, receipt_hash, vote_type) VALUES (?, ?, ?, ?, ?, ?)',
        [electionIdInt, vote.position_id, vote.candidate_id, req.session.user.code, receiptHash, voteType]
      );
      receiptHashes.push({ position_id: vote.position_id, candidate_id: vote.candidate_id, vote_type: voteType, receipt: receiptHash });
    }

    await connection.query('UPDATE users SET has_voted = 1 WHERE id = ?', [req.session.user.id]);
    await connection.commit();

    req.session.user.has_voted = 1;

    const broadcast = req.app.get('broadcastVoteUpdate');
    if (broadcast) {
      broadcast({ type: 'vote_cast', election_id: electionIdInt, timestamp: new Date().toISOString() });
    }

    res.json({ success: true, message: 'Your vote has been recorded successfully!', receipts: receiptHashes });
  } catch (err) {
    await connection.rollback();
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
});

router.get('/results/:electionId', async (req, res) => {
  try {
    const electionId = parseInt(req.params.electionId);
    if (isNaN(electionId)) return res.status(400).json({ error: 'Invalid election ID' });

    const [election] = await db.query('SELECT * FROM elections WHERE id = ?', [electionId]);
    if (election.length === 0) return res.status(404).json({ error: 'Election not found' });

    const isAdmin = req.session.user && req.session.user.role === 'admin';
    if (!isAdmin && !election[0].results_published) {
      return res.status(403).json({ error: 'Results have not been published yet', results_published: false });
    }

    const [positions] = await db.query(
      'SELECT * FROM positions WHERE election_id = ? ORDER BY sort_order, id',
      [electionId]
    );

    const results = [];
    for (const pos of positions) {
      const [candidates] = await db.query(
        `SELECT c.id, c.name, c.photo, c.manifesto,
          SUM(CASE WHEN v.vote_type = 'yes' THEN 1 ELSE 0 END) as vote_count,
          SUM(CASE WHEN v.vote_type = 'no' THEN 1 ELSE 0 END) as no_count,
          COUNT(v.id) as total_votes
         FROM candidates c LEFT JOIN votes v ON c.id = v.candidate_id AND v.election_id = ?
         WHERE c.position_id = ?
         GROUP BY c.id ORDER BY vote_count DESC`,
        [electionId, pos.id]
      );
      const [totalVotes] = await db.query(
        'SELECT COUNT(*) as total FROM votes WHERE election_id = ? AND position_id = ?',
        [electionId, pos.id]
      );
      const isSingle = candidates.length === 1;
      results.push({ name: pos.name, position_id: pos.id, candidates, total_votes: totalVotes[0].total, is_single: isSingle });
    }

    const [totalVoters] = await db.query("SELECT COUNT(*) as count FROM users WHERE role = 'voter'");
    const [totalVotesCast] = await db.query(
      'SELECT COUNT(DISTINCT voter_hash) as count FROM votes WHERE election_id = ?', [electionId]
    );

    res.json({
      election: election[0], results,
      stats: { total_voters: totalVoters[0].count, total_votes_cast: totalVotesCast[0].count }
    });
  } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

router.get('/verify-receipt/:hash', async (req, res) => {
  try {
    const hash = sanitizeInput(req.params.hash, 64);
    if (!hash || !/^[a-f0-9]+$/i.test(hash)) {
      return res.status(400).json({ error: 'Invalid receipt format' });
    }

    const [rows] = await db.query(
      `SELECT v.*, c.name as candidate_name, p.name as position_name, e.name as election_name
       FROM votes v
       JOIN candidates c ON v.candidate_id = c.id
       JOIN positions p ON v.position_id = p.id
       JOIN elections e ON v.election_id = e.id
       WHERE v.receipt_hash = ?`,
      [hash]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Receipt not found' });
    const r = rows[0];
    res.json({
      valid: true,
      election: r.election_name,
      position: r.position_name,
      candidate: r.candidate_name,
      vote_type: r.vote_type,
      voted_at: r.created_at
    });
  } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

module.exports = router;
