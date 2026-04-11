# AuthKit

A pluggable authentication library for Python applications. Zero external dependencies -- uses only the standard library.

## Features

- Token generation and validation
- Password hashing and verification
- Session management with configurable TTL
- Lightweight and easy to integrate

## Installation

```bash
pip install -r requirements.txt
```

Or just copy the modules into your project since there are no external dependencies.

## Usage

```python
from tokens import generate_token, validate_token
from passwords import hash_password, check_password
from session import SessionStore

store = SessionStore(ttl=3600)
sid = store.create(user_id=42)
data = store.get(sid)
```

## Configuration

- `AUTHKIT_SECRET`: Override the default signing secret
- `AUTHKIT_SESSION_TTL`: Session time-to-live in seconds (default: 3600)

## License

MIT
