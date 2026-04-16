/**
 * User routes — login and profile.
 * CWE-943: NoSQL injection in login query.
 * CWE-532: password logged on failed auth.
 */
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const logger = require('../lib/logger');

// POST /users/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // CWE-943: username/password can be objects e.g. {"$ne": null} to bypass auth
  const user = await db.users.findOne({ username, password });
  if (!user) {
    // CWE-532: failed password attempt logged with the actual password value
    logger.warn('Failed login for user=%s password=%s', username, password);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user._id;
  req.session.username = user.username;
  res.json({ message: 'Logged in', username: user.username });
});

// GET /users/profile?username=alice
router.get('/profile', async (req, res) => {
  // CWE-943: username from query can be {$gt: ''} to dump all users
  const user = await db.users.findOne({ username: req.query.username });
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ id: user._id, username: user.username, email: user.email });
});

module.exports = router;
