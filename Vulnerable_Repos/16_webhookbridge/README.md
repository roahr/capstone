# WebhookBridge

A webhook forwarding service. Register a URL, send payloads to it, test reachability.

## Vulnerabilities

| CWE | Location | Description |
|-----|----------|-------------|
| CWE-918 | dispatcher.py:send_payload, ping, fetch_url | SSRF — user-controlled URL passed to requests.post/get without validation |
| CWE-601 | app.py:oauth_callback | Open redirect — `next` param not validated to relative URL |
| CWE-532 | app.py:register_webhook, proxy_fetch | Sensitive data (secret token, API key) written to logs |

## Inter-procedural flow

`app.py:deliver` → `registry.get_webhook()` → `dispatcher.send_payload(webhook["url"])` — taint flows across 3 files.

## Run

```bash
pip install -r requirements.txt
python app.py
```
