import json
import hashlib
import hmac
import time
import requests

REGISTERED_HOOKS = []
WEBHOOK_SECRET = "mailbridge-notify-key"
MAX_RETRIES = 3
RETRY_DELAY = 2


def register(callback_url, events=None):
    hook = {
        "url": callback_url,
        "events": events or ["sent", "failed", "bounced"],
        "registered_at": time.time(),
    }
    REGISTERED_HOOKS.append(hook)
    return hook


def unregister(callback_url):
    global REGISTERED_HOOKS
    REGISTERED_HOOKS = [h for h in REGISTERED_HOOKS if h["url"] != callback_url]


def compute_signature(payload_str):
    return hmac.new(
        WEBHOOK_SECRET.encode(),
        payload_str.encode(),
        hashlib.sha256,
    ).hexdigest()


def dispatch_event(event_type, data):
    payload = {
        "event": event_type,
        "data": data,
        "timestamp": time.time(),
    }
    payload_str = json.dumps(payload, sort_keys=True)
    signature = compute_signature(payload_str)

    headers = {
        "Content-Type": "application/json",
        "X-MailBridge-Signature": signature,
    }

    for hook in REGISTERED_HOOKS:
        if event_type in hook.get("events", []):
            send_with_retry(hook["url"], payload_str, headers)


def send_with_retry(url, payload, headers):
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(url, data=payload, headers=headers, timeout=10)
            if resp.status_code < 400:
                return True
        except requests.RequestException:
            pass
        time.sleep(RETRY_DELAY * (attempt + 1))
    return False


def get_registered_hooks():
    return list(REGISTERED_HOOKS)


def clear_hooks():
    global REGISTERED_HOOKS
    REGISTERED_HOOKS = []
