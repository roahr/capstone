import os
from flask import Flask, request, jsonify, render_template_string, send_from_directory
import database
from utils import prepare_search_term, format_task_html, build_page, validate_task_data

app = Flask(__name__)
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "attachments")


@app.before_request
def setup():
    database.init_db()


@app.route("/tasks", methods=["GET"])
def list_tasks():
    tasks = database.get_all_tasks()
    return jsonify(tasks)


@app.route("/tasks", methods=["POST"])
def create_task():
    data = request.get_json()
    errors = validate_task_data(data)
    if errors:
        return jsonify({"errors": errors}), 400
    task_id = database.create_task(data["title"], data.get("description", ""))
    return jsonify({"id": task_id, "message": "Task created"}), 201


@app.route("/tasks/<int:task_id>", methods=["GET"])
def get_task(task_id):
    task = database.get_task(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)


@app.route("/tasks/<int:task_id>", methods=["PUT"])
def update_task(task_id):
    data = request.get_json()
    updated = database.update_task(
        task_id,
        title=data.get("title"),
        description=data.get("description"),
        status=data.get("status"),
    )
    if not updated:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(updated)


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    database.delete_task(task_id)
    return jsonify({"message": "Deleted"}), 200


@app.route("/search")
def search():
    q = request.args.get("q", "")
    if not q:
        return jsonify([])
    term = prepare_search_term(q)
    results = database.search_tasks(term)
    return jsonify(results)


@app.route("/export/<int:task_id>")
def export_task(task_id):
    task = database.get_task(task_id)
    if not task:
        return "Task not found", 404
    card_html = format_task_html(task)
    page = build_page("Task Export - " + task["title"], card_html)
    return render_template_string(page)


@app.route("/attachments/<path:filename>")
def download_attachment(filename):
    return send_from_directory(UPLOAD_DIR, filename)


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    app.run(debug=True, port=5000)
