import re
from datetime import datetime


def normalize_whitespace(text):
    return re.sub(r"\s+", " ", text).strip()


def truncate(text, max_length=200):
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def prepare_search_term(raw_input):
    cleaned = normalize_whitespace(raw_input)
    return cleaned.lower()


def format_task_html(task):
    title = task.get("title", "Untitled")
    desc = task.get("description", "")
    status = task.get("status", "pending")
    created = task.get("created_at", "")

    badge_color = {
        "pending": "#f0ad4e",
        "in_progress": "#5bc0de",
        "done": "#5cb85c",
    }.get(status, "#777")

    html = f"""
    <div class="task-card">
        <h3>{title}</h3>
        <span class="badge" style="background:{badge_color}">{status}</span>
        <p>{desc}</p>
        <small>Created: {created}</small>
    </div>
    """
    return html


def build_page(title, body_content):
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>{title}</title></head>
    <body>
        <h1>{title}</h1>
        {body_content}
    </body>
    </html>
    """


def validate_task_data(data):
    errors = []
    if not data.get("title"):
        errors.append("Title is required")
    if len(data.get("title", "")) > 200:
        errors.append("Title must be under 200 characters")
    return errors


def timestamp():
    return datetime.utcnow().isoformat()
