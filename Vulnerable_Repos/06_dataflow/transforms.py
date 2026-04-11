from datetime import datetime, timezone


def normalize_timestamps(rows):
    result = []
    for row in rows:
        row = dict(row)
        for key in ("created_at", "updated_at", "timestamp"):
            if key in row and isinstance(row[key], (int, float)):
                row[key] = datetime.fromtimestamp(row[key], tz=timezone.utc).isoformat()
        result.append(row)
    return result


def drop_columns(rows, columns):
    return [
        {k: v for k, v in row.items() if k not in columns}
        for row in rows
    ]


def rename_columns(rows, mapping):
    result = []
    for row in rows:
        new_row = {}
        for k, v in row.items():
            new_key = mapping.get(k, k)
            new_row[new_key] = v
        result.append(new_row)
    return result


def apply_expression(rows, expression):
    transformed = []
    for row in rows:
        row = dict(row)
        row["_result"] = eval(expression, {"__builtins__": {}}, {"row": row})
        transformed.append(row)
    return transformed


def _prepare_filter_value(value):
    if isinstance(value, str):
        return value.strip()
    return value


def _build_filter_criteria(column, value):
    cleaned = _prepare_filter_value(value)
    return column, cleaned


def filter_and_store(rows, column, value, connector, table):
    col, val = _build_filter_criteria(column, value)
    filtered = [r for r in rows if r.get(col) == val]
    if connector and table:
        connector.execute_query(table, {col: val})
    return filtered


def deduplicate(rows, key_column):
    seen = set()
    result = []
    for row in rows:
        key = row.get(key_column)
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result


def add_metadata(rows, source_name=None):
    now = datetime.now(tz=timezone.utc).isoformat()
    for row in rows:
        row["_processed_at"] = now
        if source_name:
            row["_source"] = source_name
    return rows
