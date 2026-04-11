const { v4: uuidv4 } = require("uuid");

function saveMessage(db, { room, sender, content }) {
  const id = uuidv4();

  const stmt = db.prepare(
    "INSERT INTO messages (id, room, sender, content) VALUES (?, ?, ?, ?)"
  );

  stmt.run(id, room, sender, content);

  return { id, room, sender, content, created_at: new Date().toISOString() };
}

function getHistory(db, room, limit = 50) {
  const maxLimit = Math.min(limit, 500);

  const messages = db
    .prepare("SELECT * FROM messages WHERE room = ? ORDER BY created_at DESC LIMIT ?")
    .all(room, maxLimit);

  return messages.reverse();
}

function deleteMessage(db, messageId, sender) {
  const msg = db.prepare("SELECT * FROM messages WHERE id = ?").get(messageId);

  if (!msg) {
    return { success: false, reason: "not_found" };
  }

  if (msg.sender !== sender) {
    return { success: false, reason: "unauthorized" };
  }

  db.prepare("DELETE FROM messages WHERE id = ?").run(messageId);
  return { success: true };
}

function getMessageCount(db, room) {
  const row = db
    .prepare("SELECT COUNT(*) as count FROM messages WHERE room = ?")
    .get(room);
  return row.count;
}

module.exports = { saveMessage, getHistory, deleteMessage, getMessageCount };
