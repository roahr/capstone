# TaskFlow

A lightweight task management API built with Flask. Designed for small teams who want a simple self-hosted alternative to Trello.

## Features

- Create, update, and delete tasks
- Search tasks by title or description
- Export task lists as formatted pages
- Download task attachments
- SQLite backend (zero config)

## Setup

```bash
pip install -r requirements.txt
python app.py
```

The server starts on `http://localhost:5000`.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/tasks` | List all tasks |
| POST | `/tasks` | Create a new task |
| GET | `/tasks/<id>` | Get task details |
| PUT | `/tasks/<id>` | Update a task |
| DELETE | `/tasks/<id>` | Delete a task |
| GET | `/search?q=` | Search tasks |
| GET | `/export/<id>` | Export task as HTML |
| GET | `/attachments/<name>` | Download attachment |

## Configuration

Set `DATABASE_PATH` environment variable to change the SQLite location (default: `./taskflow.db`).

## License

MIT
