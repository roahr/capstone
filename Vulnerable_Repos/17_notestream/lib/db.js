/**
 * MongoDB connection stub (replace with real MongoClient for live testing).
 */
const { MongoClient } = require('mongodb');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const client = new MongoClient(MONGO_URI);
const db = client.db('notestream');

module.exports = {
  notes: db.collection('notes'),
  users: db.collection('users'),
};
