import math
import pickle
import base64


BUILTIN_FUNCTIONS = {
    "avg": lambda vals, window: sum(vals[-window:]) / max(len(vals[-window:]), 1),
    "max": lambda vals, window: max(vals[-window:]),
    "min": lambda vals, window: min(vals[-window:]),
    "delta": lambda vals, _: vals[-1] - vals[0] if len(vals) > 1 else 0,
    "ceil": lambda v, _: math.ceil(v),
    "floor": lambda v, _: math.floor(v),
}


def build_eval_context(metrics):
    ctx = dict(metrics)
    ctx.update({
        "abs": abs,
        "round": round,
        "min": min,
        "max": max,
        "sum": sum,
        "len": len,
    })
    return ctx


def evaluate_expression(expression, metrics):
    ctx = build_eval_context(metrics)
    try:
        result = eval(expression, {"__builtins__": {}}, ctx)
        return result
    except Exception as e:
        return {"error": str(e)}


def load_snapshot(encoded_data):
    raw = base64.b64decode(encoded_data)
    snapshot = pickle.loads(raw)
    return snapshot


def aggregate(values, method="mean"):
    if not values:
        return 0.0
    if method == "mean":
        return sum(values) / len(values)
    elif method == "median":
        sorted_vals = sorted(values)
        mid = len(sorted_vals) // 2
        if len(sorted_vals) % 2 == 0:
            return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2
        return sorted_vals[mid]
    elif method == "p95":
        sorted_vals = sorted(values)
        idx = int(len(sorted_vals) * 0.95)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]
    return sum(values) / len(values)


def format_bytes(nbytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} PB"
