# ChatBridge

Real-time messaging server with WebSocket support and persistent history.

## Features

- WebSocket-based real-time messaging
- Room management with join/leave tracking
- Message search and history
- Bot command integration
- Persistent message storage with SQLite

## Getting Started

```bash
npm install
npm start
```

Connect via WebSocket at `ws://localhost:4000`.

## Message Protocol

```json
{
  "type": "message",
  "room": "general",
  "content": "Hello world",
  "sender": "alice"
}
```

## Bot Commands

Prefix messages with `!` to trigger bot actions:
- `!calc <expression>` — Evaluate math expressions
- `!time` — Current server time
- `!stats` — Room statistics

## License

MIT
