"""
GhostData - Privacy Risk Analyzer for Digital Files
Flask Web Application with Secure File Handling, CSRF Verification, and Isolated Storage.
"""

import os
import secrets
import time
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    send_file,
    session,
    abort
)
from werkzeug.exceptions import RequestEntityTooLarge
from analyzer.validators import validate_uploaded_file, FileValidationError, MAX_FILE_SIZE_BYTES
from analyzer.image_metadata import extract_image_metadata
from analyzer.pdf_metadata import extract_pdf_metadata
from analyzer.risk_engine import analyze_privacy_risks
from analyzer.cleaner import clean_file, CleaningError
from analyzer.verifier import verify_cleaning

app = Flask(__name__)
# Generate a cryptographically secure secret key for session signing
app.config["SECRET_KEY"] = os.environ.get("GHOSTDATA_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE_BYTES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
UPLOAD_DIR = os.path.join(STORAGE_DIR, "uploads")
CLEAN_DIR = os.path.join(STORAGE_DIR, "cleaned")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CLEAN_DIR, exist_ok=True)

# In-memory session tracking for uploaded file state
# Schema: { file_id: { "owner_session": str, "file_path": str, "file_type": str, "metadata": dict, "risk": dict, "cleaned_path": str, "verification": dict, "created_at": float } }
FILE_REGISTRY = {}


def _cleanup_expired_files(max_age_seconds: int = 3600):
    """
    Periodically purges files older than max_age_seconds (default 1 hour)
    to prevent disk accumulation and enforce data retention minimization.
    """
    now = time.time()
    expired_ids = []
    for fid, record in FILE_REGISTRY.items():
        if now - record.get("created_at", now) > max_age_seconds:
            expired_ids.append(fid)

    for fid in expired_ids:
        record = FILE_REGISTRY.pop(fid, None)
        if record:
            for path_key in ("file_path", "cleaned_path"):
                p = record.get(path_key)
                if p and os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass


@app.before_request
def ensure_session_security():
    """Initializes session ID and CSRF token for each visitor."""
    if "session_id" not in session:
        session["session_id"] = secrets.token_hex(16)
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


def _verify_csrf():
    """Checks CSRF token in request headers or form data."""
    token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        return False
    return True


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    return jsonify({
        "error": f"File exceeds maximum allowed upload size ({MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB).",
        "code": "FILE_TOO_LARGE"
    }), 413


@app.route("/")
def index():
    """Serves the main dashboard."""
    return render_template("index.html", csrf_token=session["csrf_token"])


@app.route("/api/upload", methods=["POST"])
def upload_file():
    """
    Accepts file upload, executes signature validation, extracts metadata,
    and runs the privacy risk engine.
    """
    _cleanup_expired_files()

    if not _verify_csrf():
        return jsonify({"error": "Security check failed (Invalid or missing CSRF token).", "code": "CSRF_ERROR"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file payload received in request.", "code": "NO_FILE"}), 400

    uploaded = request.files["file"]
    if not uploaded or uploaded.filename == "":
        return jsonify({"error": "No file selected.", "code": "EMPTY_SELECTION"}), 400

    original_filename = os.path.basename(uploaded.filename)

    try:
        # Validate magic bytes, size limits, and parse structure securely
        detected_type, safe_filename, full_path, file_size = validate_uploaded_file(
            uploaded.stream,
            original_filename=original_filename,
            storage_dir=UPLOAD_DIR,
            max_size_bytes=MAX_FILE_SIZE_BYTES
        )
    except FileValidationError as e:
        return jsonify({"error": e.message, "code": e.code}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected validation failure: {str(e)}", "code": "SERVER_ERROR"}), 500

    # Extract metadata according to file type
    if detected_type == "jpeg":
        metadata = extract_image_metadata(full_path)
    elif detected_type == "pdf":
        metadata = extract_pdf_metadata(full_path)
    else:
        metadata = {"file_type": "UNKNOWN", "fields": {}, "inspection_status": "FAILED"}

    # Run Privacy Risk Explanation Engine
    risk_report = analyze_privacy_risks(metadata)

    # Register record keyed by secure token
    file_id = secrets.token_urlsafe(16)
    FILE_REGISTRY[file_id] = {
        "owner_session": session["session_id"],
        "original_filename": original_filename,
        "file_path": full_path,
        "file_type": detected_type.upper(),
        "file_size": file_size,
        "metadata": metadata,
        "risk": risk_report,
        "cleaned_path": None,
        "verification": None,
        "cleaner_details": None,
        "created_at": time.time(),
    }

    return jsonify({
        "file_id": file_id,
        "original_filename": original_filename,
        "file_type": detected_type.upper(),
        "file_size_formatted": f"{file_size / 1024:.1f} KB",
        "metadata": metadata,
        "risk_report": risk_report
    })


@app.route("/api/clean", methods=["POST"])
def clean_file_endpoint():
    """
    Cleans metadata from an uploaded file and runs post-cleaning verification.
    """
    if not _verify_csrf():
        return jsonify({"error": "Security check failed (Invalid or missing CSRF token).", "code": "CSRF_ERROR"}), 403

    data = request.get_json(silent=True) or {}
    file_id = data.get("file_id")

    if not file_id or file_id not in FILE_REGISTRY:
        return jsonify({"error": "Requested file record not found or has expired.", "code": "NOT_FOUND"}), 404

    record = FILE_REGISTRY[file_id]
    if record["owner_session"] != session.get("session_id"):
        return jsonify({"error": "Access denied: file belongs to another session.", "code": "FORBIDDEN"}), 403

    try:
        # Run cleaner to create a separate sanitized copy
        cleaned_filename, cleaned_full_path, cleaner_details = clean_file(
            input_path=record["file_path"],
            file_type=record["file_type"],
            cleaned_dir=CLEAN_DIR
        )

        # Run verification: re-extract, diff, and structural check
        verification_report = verify_cleaning(
            original_metadata=record["metadata"],
            original_risk=record["risk"],
            cleaned_file_path=cleaned_full_path,
            file_type=record["file_type"],
            cleaner_notes=cleaner_details.get("notes", []),
            unsupported_structures=cleaner_details.get("unsupported_structures", [])
        )

        record["cleaned_path"] = cleaned_full_path
        record["verification"] = verification_report
        record["cleaner_details"] = cleaner_details

        return jsonify({
            "success": True,
            "file_id": file_id,
            "verification": verification_report,
            "cleaner_details": cleaner_details
        })

    except CleaningError as e:
        return jsonify({"error": str(e), "code": "CLEANING_FAILED"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal verification failure: {str(e)}", "code": "SERVER_ERROR"}), 500


@app.route("/download/<file_id>")
def download_cleaned(file_id):
    """
    Safely serves the verified sanitized file with ownership verification.
    """
    if file_id not in FILE_REGISTRY:
        abort(404, description="File not found or expired.")

    record = FILE_REGISTRY[file_id]
    if record["owner_session"] != session.get("session_id"):
        abort(403, description="Access denied.")

    cleaned_path = record.get("cleaned_path")
    if not cleaned_path or not os.path.exists(cleaned_path):
        abort(400, description="Cleaned copy has not been generated for this file.")

    ext = ".jpg" if record["file_type"] == "JPEG" else ".pdf"
    base_name = os.path.splitext(record["original_filename"])[0]
    download_name = f"{base_name}_cleaned{ext}"

    mimetype = "image/jpeg" if record["file_type"] == "JPEG" else "application/pdf"
    return send_file(cleaned_path, as_attachment=True, download_name=download_name, mimetype=mimetype)


@app.route("/report/<file_id>")
def view_report(file_id):
    """
    Renders a standalone, printable privacy analysis & verification report.
    """
    if file_id not in FILE_REGISTRY:
        abort(404, description="File report not found or expired.")

    record = FILE_REGISTRY[file_id]
    if record["owner_session"] != session.get("session_id"):
        abort(403, description="Access denied.")

    return render_template(
        "report.html",
        file_id=file_id,
        record=record
    )


if __name__ == "__main__":
    # In local development mode, bind strictly to localhost (127.0.0.1)
    app.run(host="127.0.0.1", port=5000, debug=False)
