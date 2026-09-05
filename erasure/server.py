"""
Sentinel-Purge Web Server
Module: erasure.server

Minimal Flask application providing:
  - POST /api/upload   — Accept file upload, save to uploads/ directory
  - POST /api/erasure  — Execute authorized Clear or Purge on a target file
  - GET  /             — Serve the SPA frontend from erasure/static/
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from erasure.audit_trail import AuditTrail
from erasure.handler import handle_clear, handle_purge

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload limit

# Shared audit trail instance (per-server lifetime)
audit = AuditTrail()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the SPA frontend."""
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.route("/api/upload", methods=["POST"])
def upload_file():
    """
    Accept a file upload via multipart/form-data.

    Returns JSON:
        { "path": "<absolute path>", "filename": "<original name>", "size": <bytes> }
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in request."}), 400

    file = request.files["file"]
    if file.filename == "" or file.filename is None:
        return jsonify({"error": "No file selected."}), 400

    # Save with a unique prefix to avoid collisions
    safe_name = f"{uuid.uuid4().hex[:8]}_{file.filename}"
    save_path = UPLOAD_DIR / safe_name
    file.save(str(save_path))

    file_size = save_path.stat().st_size

    return jsonify({
        "path": str(save_path.resolve()),
        "filename": file.filename,
        "size": file_size,
    }), 200


@app.route("/api/erasure", methods=["POST"])
def erasure_action():
    """
    Execute an authorized erasure operation.

    Expects JSON body:
        {
            "file_path":  "<absolute path from /api/upload>",
            "operation":  "clear" | "purge",
            "secret_key": "<user-supplied authorization key>"
        }

    Returns JSON with operation result + full audit trail.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    file_path = data.get("file_path", "").strip()
    operation = data.get("operation", "").strip().lower()
    secret_key = data.get("secret_key", "")

    if not file_path:
        return jsonify({"error": "Missing required field: file_path"}), 400
    if operation not in ("clear", "purge"):
        return jsonify({"error": "Invalid operation. Must be 'clear' or 'purge'."}), 400
    if not secret_key:
        return jsonify({"error": "Missing required field: secret_key"}), 400

    # Clear the per-request audit entries so the response only contains
    # entries relevant to this specific operation.
    trail = AuditTrail()

    if operation == "clear":
        result = handle_clear(file_path, secret_key, audit=trail)
    else:
        result = handle_purge(file_path, secret_key, audit=trail)

    status_code = 200 if result["success"] else 403 if "Authorization failed" in result["detail"] else 500
    return jsonify(result), status_code


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the development server."""
    print("=" * 60)
    print("  Sentinel-Purge Erasure Server")
    print(f"  Static dir : {STATIC_DIR}")
    print(f"  Upload dir : {UPLOAD_DIR}")
    print("  URL        : http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)


if __name__ == "__main__":
    main()
