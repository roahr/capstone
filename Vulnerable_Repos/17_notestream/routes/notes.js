/**
 * Note routes — search and retrieval.
 * CWE-943: NoSQL injection via MongoDB $where and unvalidated operator injection.
 */
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { mergeOptions } = require('../lib/utils');

// GET /notes/search?q=term&author=user
router.get('/search', async (req, res) => {
  const { q, author } = req.query;
  // CWE-943: req.query values passed directly into MongoDB query object
  // Attacker can pass: author[$ne]=admin to bypass filters
  const filter = { content: { $regex: q }, author };
  const notes = await db.notes.find(filter).toArray();
  res.json(notes);
});

// GET /notes?filter[status]=published&filter[owner]=alice
router.get('/', async (req, res) => {
  // CWE-943: nested query params merged into Mongo filter without sanitization
  const userFilter = req.query.filter || {};
  // CWE-1321: mergeOptions does recursive merge — prototype pollution possible
  const filter = mergeOptions({ deleted: false }, userFilter);
  const notes = await db.notes.find(filter).toArray();
  res.json(notes);
});

// GET /notes/:id/export?format=json
router.get('/:id/export', async (req, res) => {
  const note = await db.notes.findOne({ _id: req.params.id });
  if (!note) return res.status(404).json({ error: 'Not found' });
  const format = req.query.format || 'json';
  // CWE-943: $where clause with user-supplied content
  const related = await db.notes.find({
    $where: `this.author == '${note.author}' && this.tags.includes('${format}')`,
  }).toArray();
  res.json({ note, related });
});

module.exports = router;
