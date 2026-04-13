"""
Flask web application for the AI-Powered Secure Code Analysis Tool.
"""

import os

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    flash,
    redirect,
    url_for,
)
from werkzeug.utils import secure_filename

import config
import analyzer

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", allowed=sorted(config.ALLOWED_EXTENSIONS))


@app.route("/analyze", methods=["POST"])
def analyze():
    """Accept code via textarea or file upload and return analysis results."""
    code = ""
    filename = "code.txt"

    # --- file upload ---
    uploaded = request.files.get("file")
    if uploaded and uploaded.filename:
        if not _allowed_file(uploaded.filename):
            flash("Unsupported file type.", "danger")
            return redirect(url_for("index"))
        filename = secure_filename(uploaded.filename)
        code = uploaded.read().decode("utf-8", errors="replace")

    # --- textarea fallback ---
    if not code:
        code = request.form.get("code", "").strip()
        lang_hint = request.form.get("language", "")
        if lang_hint:
            filename = f"code.{lang_hint}"

    if not code:
        flash("Please provide source code to analyse.", "warning")
        return redirect(url_for("index"))

    result = analyzer.analyse(code, filename)
    return render_template("result.html", result=result.to_dict(), code=code)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    JSON API endpoint.

    Accepts:
        { "code": "<source>", "filename": "<optional>" }

    Returns the full AnalysisResult as JSON.
    """
    data = request.get_json(force=True, silent=True) or {}
    code = data.get("code", "").strip()
    filename = data.get("filename", "code.py")

    if not code:
        return jsonify({"error": "No code provided."}), 400

    result = analyzer.analyse(code, filename)
    return jsonify(result.to_dict())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=config.DEBUG, host="0.0.0.0", port=5000)
