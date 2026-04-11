import os
import traceback
from flask import Flask, request, jsonify, send_from_directory
from auth import require_api_key
import storage

app = Flask(__name__)

STORAGE_DIR = os.environ.get("DOCVAULT_STORAGE", "./vault")


@app.route("/api/documents", methods=["POST"])
@require_api_key
def upload_document():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    data = uploaded.read()
    filepath = storage.save_file(uploaded.filename, data, uploaded.content_type)
    return jsonify({
        "message": "Document uploaded",
        "filename": uploaded.filename,
        "size": len(data),
    }), 201


@app.route("/api/documents", methods=["GET"])
@require_api_key
def list_documents():
    docs = storage.list_files()
    return jsonify({"documents": docs, "count": len(docs)})


@app.route("/api/documents/<path:filename>", methods=["GET"])
@require_api_key
def download_document(filename):
    filepath = os.path.join(STORAGE_DIR, filename)
    if not os.path.isfile(filepath):
        return jsonify({"error": "Document not found"}), 404

    directory = os.path.dirname(filepath)
    basename = os.path.basename(filepath)
    return send_from_directory(directory, basename, as_attachment=True)


@app.route("/api/documents/<path:filename>", methods=["DELETE"])
@require_api_key
def delete_document(filename):
    docs = storage.list_files()
    exists = any(d["filename"] == filename for d in docs)
    if not exists:
        return jsonify({"error": "Document not found"}), 404

    storage.remove_file(filename)
    return jsonify({"message": "Document deleted", "filename": filename})


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "storage": STORAGE_DIR})


@app.errorhandler(Exception)
def handle_error(exc):
    return jsonify({
        "error": str(exc),
        "type": type(exc).__name__,
        "details": traceback.format_exc(),
        "storage_path": STORAGE_DIR,
        "db_path": storage.DB_PATH,
    }), 500


if __name__ == "__main__":
    port = int(os.environ.get("DOCVAULT_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
