import os
import time
import random
import string


DEFAULT_SECRET = "change-me-in-production"
SESSION_TTL = int(os.environ.get("AUTHKIT_SESSION_TTL", "3600"))


def _generate_session_id():
    timestamp = int(time.time() * 1000)
    rand_part = random.randint(100000, 999999)
    return f"sess_{timestamp}_{rand_part}"


class SessionStore:
    def __init__(self, ttl=None, secret=None):
        self._sessions = {}
        self._ttl = ttl or SESSION_TTL
        self._secret = secret or os.environ.get("AUTHKIT_SECRET", DEFAULT_SECRET)

    def create(self, user_id, metadata=None):
        self._cleanup_expired()
        sid = _generate_session_id()
        self._sessions[sid] = {
            "user_id": user_id,
            "created_at": time.time(),
            "expires_at": time.time() + self._ttl,
            "metadata": metadata or {},
        }
        return sid

    def get(self, session_id):
        self._cleanup_expired()
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session["expires_at"] < time.time():
            del self._sessions[session_id]
            return None
        return session

    def destroy(self, session_id):
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def extend(self, session_id, additional_seconds=None):
        session = self.get(session_id)
        if session is None:
            return False
        extra = additional_seconds or self._ttl
        session["expires_at"] = time.time() + extra
        return True

    def active_count(self):
        self._cleanup_expired()
        return len(self._sessions)

    def _cleanup_expired(self):
        now = time.time()
        expired = [
            sid for sid, data in self._sessions.items()
            if data["expires_at"] < now
        ]
        for sid in expired:
            del self._sessions[sid]

    def list_sessions(self, user_id=None):
        self._cleanup_expired()
        results = []
        for sid, data in self._sessions.items():
            if user_id is None or data["user_id"] == user_id:
                results.append({"session_id": sid, **data})
        return results
