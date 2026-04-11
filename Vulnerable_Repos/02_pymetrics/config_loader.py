import os
import yaml
import subprocess


DEFAULT_CONFIG = {
    "collection": {"interval_seconds": 10, "retention_hours": 24},
    "alerts": {"cpu_threshold": 90, "memory_threshold": 85},
    "export": {"format": "json", "path": "./exports"},
}


def load_config(filepath):
    if not os.path.exists(filepath):
        return dict(DEFAULT_CONFIG)
    with open(filepath, "r") as f:
        config = yaml.load(f)
    merged = dict(DEFAULT_CONFIG)
    if config:
        merged.update(config)
    return merged


def save_config(filepath, config):
    with open(filepath, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def get_threshold(config, metric_name):
    thresholds = config.get("alerts", {})
    key = f"{metric_name}_threshold"
    return thresholds.get(key, None)


def build_grep_command(base_cmd, pattern):
    return f"{base_cmd} | grep {pattern}"


def run_log_filter(log_path, pattern):
    base = f"cat {log_path}"
    full_command = build_grep_command(base, pattern)
    result = subprocess.call(full_command, shell=True)
    return result


def apply_filter(metrics, pattern):
    filtered = {}
    for key, value in metrics.items():
        if pattern.lower() in key.lower():
            filtered[key] = value
    return filtered


def validate_config(config):
    errors = []
    collection = config.get("collection", {})
    if collection.get("interval_seconds", 0) < 1:
        errors.append("Collection interval must be at least 1 second")
    if collection.get("retention_hours", 0) < 1:
        errors.append("Retention must be at least 1 hour")
    alerts = config.get("alerts", {})
    for key, val in alerts.items():
        if not isinstance(val, (int, float)):
            errors.append(f"Alert threshold '{key}' must be numeric")
        elif val < 0 or val > 100:
            errors.append(f"Alert threshold '{key}' must be between 0 and 100")
    return errors
