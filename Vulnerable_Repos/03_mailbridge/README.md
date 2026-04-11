# MailBridge

A simple SMTP relay and email forwarding service. Accepts emails via REST API and forwards them through configured SMTP servers. Supports webhooks for delivery notifications.

## Features

- REST API for sending emails
- Attachment handling and forwarding
- Recipient alias lookup
- Webhook notifications on delivery/bounce
- Configurable SMTP backends

## Setup

```bash
pip install -r requirements.txt
python server.py
```

Runs on `http://localhost:6000` by default.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/send` | Send an email |
| POST | `/forward` | Forward with alias resolution |
| GET | `/status/<msg_id>` | Check delivery status |
| POST | `/webhook/register` | Register delivery webhook |
| POST | `/process-attachment` | Process and relay attachment |

## Configuration

Set the following environment variables:

- `SMTP_HOST` - SMTP server hostname
- `SMTP_PORT` - SMTP port (default: 587)
- `SMTP_USER` - Authentication username
- `SMTP_PASS` - Authentication password
- `DB_PATH` - SQLite path for recipient mappings

## License

MIT
