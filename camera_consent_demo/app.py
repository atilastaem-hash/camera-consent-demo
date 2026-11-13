from __future__ import annotations

import secrets
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, session
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = BASE_DIR / "captures"
CAPTURE_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB maximum upload


@app.get("/")
def index():
    # Per-browser session token prevents cross-site upload requests.
    csrf_token = secrets.token_urlsafe(32)
    session["csrf_token"] = csrf_token
    return render_template("index.html", csrf_token=csrf_token)


@app.post("/upload")
def upload():
    supplied_token = request.headers.get("X-CSRF-Token", "")
    expected_token = session.get("csrf_token", "")
    if not expected_token or not secrets.compare_digest(supplied_token, expected_token):
        abort(403, description="Invalid session token. Reload the page and try again.")

    image = request.files.get("photo")
    if image is None or image.mimetype != "image/jpeg":
        abort(400, description="A JPEG photo is required.")

    data = image.read()
    if len(data) < 4 or not data.startswith(b"\xff\xd8\xff"):
        abort(400, description="The uploaded file is not a valid JPEG image.")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    random_suffix = secrets.token_hex(4)
    filename = secure_filename(f"consented_photo_{timestamp}_{random_suffix}.jpg")
    destination = CAPTURE_DIR / filename
    destination.write_bytes(data)

    # Allow one successful capture per page session.
    session.pop("csrf_token", None)
    return jsonify({"ok": True, "message": "Photo received and saved on the computer."})


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"ok": False, "error": "The photo is too large (5 MB maximum)."}), 413


if __name__ == "__main__":
    print("Consent-based camera demo is running at http://localhost:5000")
    print(f"Photos will be saved in: {CAPTURE_DIR}")
    # The Cloudflare Tunnel connects to this local-only development server.
    app.run(host="127.0.0.1", port=5000, debug=False)
