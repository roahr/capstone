import os
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify
import requests
from forwarder import resolve_and_forward
from webhook import dispatch_event

app = Flask(__name__)

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")


def send_email(to_addr, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_addr
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
    return True


@app.route("/send", methods=["POST"])
def send():
    data = request.get_json()
    to = data.get("to")
    subject = data.get("subject", "(no subject)")
    body = data.get("body", "")
    if not to:
        return jsonify({"error": "Recipient required"}), 400
    try:
        send_email(to, subject, body)
        dispatch_event("sent", {"to": to, "subject": subject})
        return jsonify({"status": "sent"})
    except Exception as e:
        dispatch_event("failed", {"to": to, "error": str(e)})
        return jsonify({"error": str(e)}), 500


@app.route("/forward", methods=["POST"])
def forward():
    data = request.get_json()
    alias = data.get("alias")
    subject = data.get("subject", "")
    body = data.get("body", "")
    if not alias:
        return jsonify({"error": "Alias required"}), 400
    result = resolve_and_forward(alias, subject, body)
    return jsonify(result)


@app.route("/process-attachment", methods=["POST"])
def process_attachment():
    data = request.get_json()
    file_path = data.get("path", "")
    recipient = data.get("to", "")
    if not file_path or not recipient:
        return jsonify({"error": "Path and recipient required"}), 400
    converter = os.environ.get("ATTACHMENT_CONVERTER", "libreoffice --headless --convert-to pdf")
    os.system(f"{converter} {file_path}")
    return jsonify({"status": "processed", "recipient": recipient})


@app.route("/webhook/register", methods=["POST"])
def register_webhook():
    data = request.get_json()
    callback_url = data.get("url")
    if not callback_url:
        return jsonify({"error": "URL required"}), 400
    response = requests.get(callback_url, timeout=5)
    if response.status_code == 200:
        return jsonify({"status": "registered", "url": callback_url})
    return jsonify({"error": "Callback URL not reachable"}), 400


@app.route("/status/<msg_id>")
def message_status(msg_id):
    return jsonify({"msg_id": msg_id, "status": "delivered"})


if __name__ == "__main__":
    app.run(debug=True, port=6000)
