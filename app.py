from __future__ import annotations

import csv
import io
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Callable

from dotenv import load_dotenv
from flask import (Flask, abort, flash, g, make_response, redirect, render_template,
                   request, send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from report_generator import generate_pdf

from scanner import ScanError, scan_site

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__, instance_relative_config=True)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", ""),
    DATABASE=str((BASE_DIR / os.getenv("DATABASE_PATH", "instance/wapt.db")).resolve()),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("APP_ENV", "development").lower() == "production",
    MAX_CONTENT_LENGTH=32 * 1024,
)
if not app.config["SECRET_KEY"] or app.config["SECRET_KEY"] == "replace-this-with-a-long-random-secret":
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    print("[WAPT] Set FLASK_SECRET_KEY in .env to keep sessions valid across restarts.")

Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = sqlite3.connect(app.config["DATABASE"])
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            final_url TEXT,
            status TEXT NOT NULL,
            http_status INTEGER,
            score INTEGER,
            duration_seconds REAL,
            response_time_ms INTEGER,
            counts_json TEXT NOT NULL DEFAULT '{}',
            scope_note TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            scanner_version TEXT,
            methodology_version TEXT,
            coverage_json TEXT NOT NULL DEFAULT '{}',
            assessment_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            cwe TEXT,
            affected_url TEXT,
            confidence TEXT,
            fingerprint TEXT,
            observation_type TEXT,
            impact TEXT,
            verification TEXT,
            detection_method TEXT,
            detected_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
    """)
    scan_columns = {row[1] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
    scan_migrations = {
        "scanner_version": "TEXT",
        "methodology_version": "TEXT",
        "coverage_json": "TEXT NOT NULL DEFAULT '{}'",
        "assessment_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for column, column_type in scan_migrations.items():
        if column not in scan_columns:
            db.execute(f"ALTER TABLE scans ADD COLUMN {column} {column_type}")
    finding_columns = {row[1] for row in db.execute("PRAGMA table_info(findings)").fetchall()}
    finding_migrations = {
        "affected_url": "TEXT",
        "confidence": "TEXT",
        "fingerprint": "TEXT",
        "observation_type": "TEXT",
        "impact": "TEXT",
        "verification": "TEXT",
        "detection_method": "TEXT",
        "detected_at": "TEXT",
    }
    for column, column_type in finding_migrations.items():
        if column not in finding_columns:
            db.execute(f"ALTER TABLE findings ADD COLUMN {column} {column_type}")
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        username = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
        password = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), datetime.now(timezone.utc).isoformat()),
        )
    db.commit()
    db.close()


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_globals() -> dict[str, object]:
    return {"csrf_token": csrf_token, "current_user": session.get("username"),
            "now_label": datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")}


@app.before_request
def protect_posts() -> None:
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            abort(400, description="The form security token is invalid. Refresh the page and try again.")


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
    return response


def login_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def scan_row_to_dict(row: sqlite3.Row) -> dict[str, object]:
    item = dict(row)
    item["counts"] = json.loads(item.pop("counts_json") or "{}")
    item["coverage"] = json.loads(item.pop("coverage_json") or "{}")
    item["assessment"] = json.loads(item.pop("assessment_json") or "{}")
    return item


def get_scan_or_404(scan_id: int):
    row = get_db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        abort(404)
    scan = scan_row_to_dict(row)
    scan["findings"] = [dict(r) for r in get_db().execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, category, title",
        (scan_id,),
    ).fetchall()]
    return scan


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username", "").strip(),)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            flash("Welcome back. Your assessment workspace is ready.", "success")
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.get("/")
def home():
    """Public WAPT product landing page."""
    return render_template("home.html")


@app.get("/dashboard")
@login_required
def dashboard():
    db = get_db()
    total_scans = db.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'").fetchone()[0]
    open_findings = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    high_risk = db.execute("SELECT COUNT(*) FROM findings WHERE severity IN ('critical', 'high')").fetchone()[0]
    avg_row = db.execute("SELECT AVG(score) FROM scans WHERE status = 'completed'").fetchone()
    average_score = round(avg_row[0]) if avg_row and avg_row[0] is not None else None
    recent = [scan_row_to_dict(row) for row in db.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT 8").fetchall()]
    return render_template("dashboard.html", total_scans=total_scans, open_findings=open_findings,
                           high_risk=high_risk, average_score=average_score, recent=recent)


@app.post("/scan")
@login_required
def create_scan():
    target = request.form.get("target", "").strip()
    if request.form.get("authorized") != "yes":
        flash("Confirm that you own the target or have written authorization to test it.", "error")
        return redirect(url_for("dashboard"))
    if not target:
        flash("Enter a target URL to start the assessment.", "error")
        return redirect(url_for("dashboard"))

    created_at = datetime.now(timezone.utc).isoformat()
    db = get_db()
    try:
        result = scan_site(target)
        cursor = db.execute(
            """INSERT INTO scans (
                target, final_url, status, http_status, score, duration_seconds,
                response_time_ms, counts_json, scope_note, created_at,
                scanner_version, methodology_version, coverage_json, assessment_json
            ) VALUES (?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (result["target"], result["final_url"], result["http_status"], result["score"],
             result["duration_seconds"], result["response_time_ms"], json.dumps(result["counts"]),
             result["scope_note"], created_at, result["scanner_version"],
             result["methodology_version"], json.dumps(result["coverage"]),
             json.dumps({"reconnaissance": result["reconnaissance"], "observations": result["observations"]}, ensure_ascii=False)),
        )
        scan_id = cursor.lastrowid
        for finding in result["findings"]:
            db.execute(
                """INSERT INTO findings (
                    scan_id, title, category, severity, description, evidence,
                    recommendation, cwe, affected_url, confidence, fingerprint,
                    observation_type, impact, verification, detection_method, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, finding["title"], finding["category"], finding["severity"],
                 finding["description"], finding["evidence"], finding["recommendation"],
                 finding["cwe"], finding.get("affected_url", ""), finding.get("confidence", ""),
                 finding.get("fingerprint", ""), finding.get("observation_type", ""),
                 finding.get("impact", ""), finding.get("verification", ""),
                 finding.get("detection_method", ""), finding.get("detected_at", "")),
            )
        db.commit()
        flash("Assessment completed. Review the findings and remediation guidance.", "success")
        return redirect(url_for("scan_detail", scan_id=scan_id))
    except ScanError as exc:
        db.rollback()
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))
    except Exception:
        db.rollback()
        app.logger.exception("Unexpected assessment error")
        flash("The assessment could not be completed due to an unexpected internal error.", "error")
        return redirect(url_for("dashboard"))


@app.get("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    scan = get_scan_or_404(scan_id)
    return render_template("scan_detail.html", scan=scan)


def compare_assessments(previous: dict[str, object], current: dict[str, object]) -> dict[str, object]:
    previous_by_fingerprint = {
        str(item.get("fingerprint") or ""): item
        for item in previous["findings"]
        if item.get("fingerprint")
    }
    current_by_fingerprint = {
        str(item.get("fingerprint") or ""): item
        for item in current["findings"]
        if item.get("fingerprint")
    }
    new = [item for key, item in current_by_fingerprint.items() if key not in previous_by_fingerprint]
    persistent = [item for key, item in current_by_fingerprint.items() if key in previous_by_fingerprint]
    current_tested = current.get("coverage", {}).get("checks", {})
    resolved = []
    for key, item in previous_by_fingerprint.items():
        if key in current_by_fingerprint:
            continue
        category = str(item.get("category", ""))
        title = str(item.get("title", ""))
        relevant_check_tested = any(
            category.lower() in str(check_name).lower()
            or str(check_name).lower() in category.lower()
            or str(check_name).lower() in title.lower()
            for check_name, status in current_tested.items()
            if status == "tested"
        )
        if relevant_check_tested:
            resolved.append(item)
    changed = []
    for key, item in current_by_fingerprint.items():
        old = previous_by_fingerprint.get(key)
        if old and (old.get("severity") != item.get("severity") or old.get("evidence") != item.get("evidence")):
            changed.append({"previous": old, "current": item})
    return {
        "previous": previous,
        "current": current,
        "new": new,
        "resolved": resolved,
        "persistent": persistent,
        "changed": changed,
    }


@app.get("/scan/<int:scan_id>/compare")
@login_required
def compare_latest(scan_id: int):
    current = get_scan_or_404(scan_id)
    previous_row = get_db().execute(
        "SELECT id FROM scans WHERE target = ? AND id != ? AND status = 'completed' "
        "ORDER BY created_at DESC LIMIT 1",
        (current["target"], scan_id),
    ).fetchone()
    if not previous_row:
        flash("No previous assessment for this target is available to compare.", "error")
        return redirect(url_for("scan_detail", scan_id=scan_id))
    previous = get_scan_or_404(previous_row["id"])
    comparison = compare_assessments(previous, current)
    return render_template("scan_comparison.html", scan=current, comparison=comparison)


@app.get("/scan/<int:scan_id>/export.json")
@login_required
def export_json(scan_id: int):
    scan = get_scan_or_404(scan_id)
    payload = {
        "scan_id": scan["id"], "target": scan["target"], "final_url": scan["final_url"],
        "status": scan["status"], "http_status": scan["http_status"], "score": scan["score"],
        "duration_seconds": scan["duration_seconds"], "response_time_ms": scan["response_time_ms"],
        "counts": scan["counts"], "created_at": scan["created_at"], "scope_note": scan["scope_note"],
        "coverage": scan["coverage"], "scanner_version": scan["scanner_version"],
        "methodology_version": scan["methodology_version"], "assessment": scan["assessment"],
        "findings": scan["findings"],
    }
    content = json.dumps(payload, indent=2, ensure_ascii=False)
    return send_file(io.BytesIO(content.encode("utf-8")), mimetype="application/json",
                     as_attachment=True, download_name=f"wapt-scan-{scan_id}.json")


@app.get("/scan/<int:scan_id>/export.csv")
@login_required
def export_csv(scan_id: int):
    scan = get_scan_or_404(scan_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "Target", "Final URL", "Score", "Severity", "Category", "Finding",
                     "Affected URL", "Confidence", "Observation Type", "Description", "Evidence",
                     "Impact", "Recommendation", "Verification", "Detection Method", "CWE", "Fingerprint"])
    if scan["findings"]:
        for item in scan["findings"]:
            writer.writerow([scan["id"], scan["target"], scan["final_url"], scan["score"], item["severity"], item["category"],
                             item["title"], item.get("affected_url", ""), item.get("confidence", ""),
                             item.get("observation_type", ""), item["description"], item["evidence"],
                             item.get("impact", ""), item["recommendation"], item.get("verification", ""),
                             item.get("detection_method", ""), item["cwe"], item.get("fingerprint", "")])
    else:
        writer.writerow([scan["id"], scan["target"], scan["final_url"], scan["score"], "none", "",
                         "No findings recorded", "", "", "", "", "", "", "", "", "", "", ""])
    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="wapt-scan-{scan_id}.csv"'
    return response


@app.get("/scan/<int:scan_id>/export.pdf")
@login_required
def export_pdf(scan_id: int):
    scan = get_scan_or_404(scan_id)
    pdf = generate_pdf(scan)
    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"wapt-scan-{scan_id}.pdf",
        last_modified=None,
    )


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "The request was invalid.")), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page or scan was not found."), 404


with app.app_context():
    init_db()

if __name__ == "__main__":
    # Local-only binding is intentional; do not expose this development server to the internet.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
