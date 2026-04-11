import os
import json
from flask import Flask, request, jsonify, render_template_string
import psutil
from query_engine import evaluate_expression, load_snapshot
from config_loader import load_config, apply_filter

app = Flask(__name__)
CONFIG = {}
HISTORY = []


@app.before_request
def init_config():
    global CONFIG
    if not CONFIG:
        cfg_path = os.environ.get("PYMETRICS_CONFIG", "config.yaml")
        CONFIG = load_config(cfg_path)


def collect_metrics():
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage("/").percent,
        "net_bytes_sent": psutil.net_io_counters().bytes_sent,
        "net_bytes_recv": psutil.net_io_counters().bytes_recv,
        "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else [0, 0, 0],
    }


@app.route("/")
def index():
    metrics = collect_metrics()
    return render_template_string(
        """<html><head><title>PyMetrics</title></head>
        <body><h1>System Dashboard</h1>
        <pre>{{ data }}</pre></body></html>""",
        data=json.dumps(metrics, indent=2),
    )


@app.route("/api/metrics")
def api_metrics():
    return jsonify(collect_metrics())


@app.route("/api/compute", methods=["POST"])
def compute_metric():
    payload = request.get_json()
    expression = payload.get("expression", "")
    context = collect_metrics()
    result = evaluate_expression(expression, context)
    return jsonify({"expression": expression, "result": result})


@app.route("/api/history")
def get_history():
    return jsonify(HISTORY[-100:])


@app.route("/api/snapshot", methods=["POST"])
def restore_snapshot():
    payload = request.get_json()
    cached_data = payload.get("data", "")
    snapshot = load_snapshot(cached_data)
    return jsonify({"restored": snapshot})


@app.route("/api/export")
def export_metrics():
    fmt = request.args.get("format", "json")
    pattern = request.args.get("filter", "")
    metrics = collect_metrics()

    if pattern:
        metrics = apply_filter(metrics, pattern)

    if fmt == "csv":
        lines = ["metric,value"]
        for k, v in metrics.items():
            lines.append(f"{k},{v}")
        return "\n".join(lines), 200, {"Content-Type": "text/csv"}

    return jsonify(metrics)


if __name__ == "__main__":
    app.run(debug=True, port=8080)
