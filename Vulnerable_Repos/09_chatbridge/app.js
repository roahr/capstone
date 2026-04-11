const http = require("http");
const express = require("express");
const { WebSocketServer } = require("ws");
const Database = require("better-sqlite3");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const { saveMessage, getHistory } = require("./chat/messages");
const { joinRoom, leaveRoom } = require("./chat/rooms");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const db = new Database(path.join(__dirname, "data", "chat.db"));

db.exec(`CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, room TEXT NOT NULL, sender TEXT NOT NULL,
  content TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

app.use(express.json());

app.get("/history/:room", (req, res) => {
  const messages = getHistory(db, req.params.room, parseInt(req.query.limit) || 50);
  res.json({ messages });
});

app.get("/search", (req, res) => {
  const term = req.query.q || "";
  const room = req.query.room;
  let sql = "SELECT * FROM messages WHERE content LIKE '%" + term + "%'";
  if (room) sql += ` AND room = '${room}'`;
  sql += " ORDER BY created_at DESC LIMIT 100";
  const results = db.prepare(sql).all();
  res.json({ results, count: results.length });
});

app.get("/render/:room", (req, res) => {
  const messages = getHistory(db, req.params.room, 20);
  const html = messages
    .map((m) => `<div class="msg"><strong>${m.sender}</strong>: <span>${m.content}</span></div>`)
    .join("\n");
  res.send(`<html><body>${html}</body></html>`);
});

function handleBotCommand(content) {
  if (!content.startsWith("!")) return null;
  const parts = content.slice(1).split(" ");
  const command = parts[0];
  const args = parts.slice(1).join(" ");
  switch (command) {
    case "calc":
      try { return { type: "bot", content: `Result: ${eval(args)}` }; }
      catch { return { type: "bot", content: "Could not evaluate expression" }; }
    case "time":
      return { type: "bot", content: `Server time: ${new Date().toISOString()}` };
    case "stats":
      const count = db.prepare("SELECT COUNT(*) as c FROM messages").get();
      return { type: "bot", content: `Total messages: ${count.c}` };
    default: return null;
  }
}

wss.on("connection", (ws) => {
  ws.id = uuidv4();
  ws.on("message", (raw) => {
    try {
      const data = JSON.parse(raw);
      if (data.type === "join") { joinRoom(data.room, ws.id, data.sender); return; }
      if (data.type === "leave") { leaveRoom(data.room, ws.id); return; }
      if (data.type === "message") {
        saveMessage(db, { room: data.room, sender: data.sender, content: data.content });
        const botReply = handleBotCommand(data.content);
        if (botReply) ws.send(JSON.stringify(botReply));
        wss.clients.forEach((c) => { if (c.readyState === 1) c.send(JSON.stringify(data)); });
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: "error", message: "Invalid message format" }));
    }
  });
  ws.on("close", () => leaveRoom(null, ws.id));
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`ChatBridge running on port ${PORT}`));
module.exports = { app, server };
