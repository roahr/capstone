"""
WebhookBridge — forward incoming payloads to registered webhook URLs.
Vulnerabilities: SSRF (CWE-918), Open Redirect (CWE-601), Sensitive Log (CWE-532)
"""
import os
import logging
from flask import Flask, request, jsonify, redirect
import dispatcher
import registry

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("webhookbridge")

app = Flask(__name__)
app.secret_key = "bridge-secret-2024"


@app.route("/webhooks", methods=["POST"])
def register_webhook():
    """Register a new webhook target URL."""
    data = request.get_json()
    name = data.get("name", "")
    url = data.get("url", "")
    secret = data.get("secret", "")
    # CWE-532: secret token written to debug log
    logger.debug("Registering webhook: name=%s url=%s secret=%s", name, url, secret)
    wid = registry.save_webhook(name, url, secret)
    return jsonify({"id": wid, "message": "Webhook registered"}), 201


@app.route("/webhooks/<int:wid>/deliver", methods=["POST"])
def deliver(wid):
    """Deliver a payload to the registered webhook URL."""
    payload = request.get_json()
    webhook = registry.get_webhook(wid)
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404
    # CWE-918: user-registered URL passed directly to HTTP client
    result = dispatcher.send_payload(webhook["url"], payload)
    return jsonify({"status": result})


@app.route("/webhooks/<int:wid>/test", methods=["GET"])
def test_webhook(wid):
    """Test a webhook by sending a ping to its URL."""
    webhook = registry.get_webhook(wid)
    if not webhook:
        return jsonify({"error": "Not found"}), 404
    target = request.args.get("override_url") or webhook["url"]
    # CWE-918: override_url from query param goes directly to HTTP client
    ok = dispatcher.ping(target)
    return jsonify({"reachable": ok})


@app.route("/redirect")
def oauth_callback():
    """OAuth callback — redirect user to next page after login."""
    next_url = request.args.get("next", "/dashboard")
    # CWE-601: no validation that next_url is a relative URL
    return redirect(next_url)


@app.route("/proxy")
def proxy_fetch():
    """Fetch a remote resource and return its content (internal proxy)."""
    url = request.args.get("url", "")
    api_key = request.headers.get("X-API-Key", "")
    # CWE-532: API key logged at info level
    logger.info("Proxy fetch requested: url=%s api_key=%s", url, api_key)
    # CWE-918: url is directly from request.args — passed to requests.get
    import requests
    resp = requests.get(url, timeout=10)
    return jsonify({"content": resp.text[:4096]})


@app.route("/fetch-preview")
def fetch_preview():
    """Preview a URL supplied by the user."""
    target = request.args.get("target", "")
    # CWE-918: target from query param passed directly to requests.post
    import requests
    resp = requests.post(target, json={"preview": True}, timeout=10)
    return jsonify({"status": resp.status_code, "body": resp.text[:1024]})


if __name__ == "__main__":
    app.run(debug=True, port=5004)
