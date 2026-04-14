"""
Dispatcher: makes outbound HTTP requests on behalf of the platform.
CWE-918: all HTTP client calls accept arbitrary URLs from upstream callers.
"""
import requests
import logging

logger = logging.getLogger("webhookbridge.dispatcher")

TIMEOUT = 10


def send_payload(url: str, payload: dict) -> str:
    """POST payload to target URL — no URL validation performed."""
    try:
        # CWE-918: url comes from user-registered webhook record
        resp = requests.post(url, json=payload, timeout=TIMEOUT)
        logger.debug("Delivered to %s — status %s", url, resp.status_code)
        return "ok" if resp.ok else f"error:{resp.status_code}"
    except Exception as exc:
        logger.error("Delivery failed for %s: %s", url, exc)
        return "failed"


def ping(url: str) -> bool:
    """GET request to url — checks reachability."""
    try:
        # CWE-918: url may be http://169.254.169.254/ (IMDS), internal services, etc.
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return resp.status_code < 400
    except Exception:
        return False


def fetch_url(url: str) -> str:
    """Fetch arbitrary URL and return response body — server-side proxy."""
    try:
        # CWE-918: completely unvalidated URL — SSRF to any host
        resp = requests.get(url, timeout=TIMEOUT)
        return resp.text
    except Exception as exc:
        return f"error: {exc}"
