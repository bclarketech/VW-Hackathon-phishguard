"""
PhishGuard web app.

Security posture (deliberate, and worth calling out in the write-up):
  * debug is NEVER enabled — run under gunicorn, not app.run(debug=True).
  * Pasted emails are analyzed in memory only; nothing is written to disk,
    logged, or sent anywhere.
  * No authentication — it's a read-only analyzer for a classroom demo.
"""

from flask import Flask, render_template, request, jsonify

from analyzer import analyze

app = Flask(__name__)

# Hard cap so a huge paste can't chew through memory.
MAX_PASTE_CHARS = 50_000


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", report=None, error=None,
                           sender="", subject="", body="")


@app.route("/analyze", methods=["POST"])
def analyze_route():
    # Supports both a normal form post and an AJAX JSON post.
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        subject = (payload.get("subject") or "").strip()
        sender = (payload.get("sender") or "").strip()
        body = (payload.get("body") or "").strip()
        raw = (payload.get("raw") or "").strip()
    else:
        subject = (request.form.get("subject") or "").strip()
        sender = (request.form.get("sender") or "").strip()
        body = (request.form.get("body") or "").strip()
        raw = (request.form.get("raw") or "").strip()

        # Also accept a directly-uploaded email file (e.g. .eml / .txt).
        # Read it in memory only — never written to disk.
        upload = request.files.get("raw_file")
        if upload and upload.filename and not raw:
            try:
                raw = upload.read(MAX_PASTE_CHARS + 1).decode("utf-8", errors="replace").strip()
            except Exception:
                raw = ""

    # Enforce the size limit on whatever the user gave us.
    # NOTE: on every branch we echo the input back so the user never loses
    #       what they pasted (nothing is persisted server-side).
    echo_body = body or raw
    total = len(subject) + len(sender) + len(body) + len(raw)
    if total > MAX_PASTE_CHARS:
        error = f"Input too large ({total:,} chars). Please paste under {MAX_PASTE_CHARS:,} characters."
        if request.is_json:
            return jsonify({"error": error}), 413
        return render_template("index.html", report=None, error=error,
                               sender=sender, subject=subject, body=echo_body), 413

    if not (subject or body or raw):
        error = "Paste an email (or fill in at least the body) to analyze."
        if request.is_json:
            return jsonify({"error": error}), 400
        return render_template("index.html", report=None, error=error,
                               sender=sender, subject=subject, body=echo_body), 400

    report = analyze(subject=subject, body=body, sender=sender, raw=raw)

    # NOTE: we intentionally do not store `report`, `body`, or `raw` anywhere.
    # The values below are only echoed back into the response form.
    if request.is_json:
        return jsonify(report.as_dict())
    return render_template("index.html", report=report, error=None,
                           sender=sender, subject=subject, body=echo_body)


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    # Local development only. Production MUST use gunicorn:
    #   gunicorn -w 2 -b 127.0.0.1:8000 app:app
    app.run(host="127.0.0.1", port=8000, debug=False)
