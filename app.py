"""
ISMS Compliance Tracker
=======================

A web application for managing an ISO/IEC 27001:2022 Information Security
Management System: the Annex A control library, the risk register, the
document register, the Statement of Applicability, and the internal audit
and corrective action cycle.

Run with:
    python seed.py     (once, to build the database)
    python app.py
    open http://127.0.0.1:5000
"""

import csv
import hmac
import io
import os
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db

app = Flask(__name__)

# Signs the session cookie. Set SECRET_KEY in the environment (and in the
# Vercel project settings); without it a random key is made at start-up, so
# everyone is logged out whenever the app restarts.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("VERCEL")),
    # Largest request accepted: one 10 MB evidence file plus the form around it.
    MAX_CONTENT_LENGTH=10 * 1024 * 1024 + 64 * 1024,
)

# Build the database on first use. On a serverless host the working copy lives
# on an ephemeral disk, so each cold start seeds its own database; importing
# seed is not enough, build() has to be called explicitly.
if not os.path.exists(db.DB_PATH):
    import seed

    seed.build()
db.ensure_tables()

TODAY = db.TODAY


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

@app.context_processor
def inject_helpers():
    tasks = db.open_tasks(g.user["id"]) if g.get("user") else []
    return {
        "my_task_count": len(tasks),
        "my_overdue_count": len(db.overdue(tasks)),
        "people": db.people,
        "risk_score": db.risk_score,
        "risk_level": db.risk_level,
        "risk_level_class": db.risk_level_class,
        "status_class": status_class,
        "today": TODAY,
        "can_write": can_write,
        "csrf_token": csrf_token,
        "roles": db.ROLES,
        "field_label": lambda f: db.FIELD_LABELS.get(f, f),
        "activity_url": activity_url,
        "uploads_are_temporary": db.UPLOADS_ARE_TEMPORARY,
        "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
    }


def status_class(status):
    return {
        "Not Started": "st-none",
        "In Progress": "st-prog",
        "Implemented": "st-impl",
        "Verified": "st-ver",
        "Draft": "st-none",
        "Under Review": "st-prog",
        "Approved": "st-ver",
        "Obsolete": "st-obs",
        "Open": "st-none",
        "In Treatment": "st-prog",
        "Closed": "st-ver",
        "Major": "lvl-crit",
        "Minor": "lvl-high",
        "Observation": "lvl-med",
        "OFI": "lvl-low",
    }.get(status, "st-none")


def days_until(datestr):
    if not datestr:
        return None
    try:
        return (datetime.strptime(datestr, "%Y-%m-%d").date() - TODAY).days
    except ValueError:
        return None


app.jinja_env.filters["days_until"] = days_until


def ago(stamp):
    """'2025-01-23 10:04:00' (UTC) -> '5 min ago', '2h ago', '3 days ago'."""
    try:
        then = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return stamp
    seconds = int((datetime.now(timezone.utc) - then).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    days = seconds // 86400
    if days < 30:
        return f"{days} day{'s' if days > 1 else ''} ago"
    return then.strftime("%d %b %Y")


app.jinja_env.filters["ago"] = ago


def parse_assignee(value):
    """A submitted 'Assigned to' value -> a real user id, or None."""
    try:
        user_id = int(value)
    except (TypeError, ValueError):
        return None
    return user_id if db.query("SELECT 1 FROM users WHERE id = ?", (user_id,), one=True) else None


def parse_date(value):
    """'YYYY-MM-DD' or None. Anything else is dropped rather than stored."""
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return None


def task_url(t):
    if t["kind"] == "control":
        return url_for("control_detail", ref=t["ref"])
    if t["kind"] == "risk":
        return url_for("risk_form", risk_id=t["id"])
    return url_for("finding_form", finding_id=t["id"])


def activity_url(a):
    """Where an activity row should link to, or None."""
    if a["action"] == "deleted":
        return None
    if a["entity_type"] == "control":
        return url_for("control_detail", ref=a["entity_ref"])
    if a["entity_type"] == "clause":
        return url_for("clauses")
    if a["entity_type"] == "risk" and a["entity_id"]:
        return url_for("risk_form", risk_id=a["entity_id"])
    if a["entity_type"] == "document" and a["entity_id"]:
        return url_for("document_form", doc_id=a["entity_id"])
    if a["entity_type"] == "finding" and a["entity_id"]:
        return url_for("finding_form", finding_id=a["entity_id"])
    if a["entity_type"] == "user" and g.user and g.user["role"] == "admin":
        return url_for("users")
    return None


# ---------------------------------------------------------------------------
# Sign-in, roles and form protection
# ---------------------------------------------------------------------------

# Pages anyone may open without signing in.
PUBLIC_ENDPOINTS = {"login", "static"}

# Pages every signed-in user may submit, whatever their role.
SELF_SERVICE_ENDPOINTS = {"logout", "profile"}

ADMIN_ENDPOINTS = {"users", "user_update", "delete_item"}

MIN_PASSWORD = 8


def can_write(endpoint):
    """May the signed-in user submit (POST) the form behind this endpoint?"""
    user = g.get("user")
    if not user:
        return False
    if endpoint in SELF_SERVICE_ENDPOINTS or user["role"] == "admin":
        return True
    if endpoint in ADMIN_ENDPOINTS:
        return False
    if user["role"] == "editor":
        return True
    if user["role"] == "auditor":
        return endpoint in ("finding_form", "comment_add")
    return False


def csrf_token():
    """A random per-session token every POST form must send back.

    It stops another website from making a signed-in user's browser submit
    a form here (cross-site request forgery).
    """
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def gatekeeper():
    """One check in front of every page: signed in, allowed, genuine form."""
    g.user = None
    if "user_id" in session:
        g.user = db.query("SELECT * FROM users WHERE id = ?", (session["user_id"],), one=True)
        if g.user is None:          # account removed, or the database was rebuilt
            session.clear()

    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(session.get("csrf", ""), sent):
            abort(400, "This form has expired. Go back, reload the page and try again.")

    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if g.user is None:
        return redirect(url_for("login", next=request.full_path.rstrip("?")))
    if request.method == "POST" and not can_write(request.endpoint):
        abort(403)
    if request.endpoint in ADMIN_ENDPOINTS and g.user["role"] != "admin":
        abort(403)
    return None


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def error_page(err):
    if err.code == 403:
        role = g.user["role"] if g.get("user") else "guest"
        message = f"Your role ({role}) is not allowed to do this."
    elif err.code == 413:
        message = f"That file is too big. The limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
    elif err.code == 404:
        message = "That page or file does not exist."
    else:
        message = err.description
    return render_template("error.html", code=err.code, message=message), err.code


def safe_next(target):
    """Only follow ?next= links that stay on this site."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()             # fresh session: no fixation, new CSRF token
            session["user_id"] = user["id"]
            return redirect(safe_next(request.args.get("next")))
        # Same message either way, so the form does not reveal which emails exist.
        error = "Email or password is wrong."

    return render_template("login.html", error=error), 401 if error else 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    error = None
    if request.method == "POST":
        f = request.form
        if not check_password_hash(g.user["password_hash"], f.get("current", "")):
            error = "Your current password is wrong."
        elif len(f.get("new", "")) < MIN_PASSWORD:
            error = f"The new password must be at least {MIN_PASSWORD} characters."
        elif f.get("new") != f.get("confirm"):
            error = "The two new passwords do not match."
        else:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(f["new"]), g.user["id"]),
            )
            db.log(g.user, "user", g.user["id"], g.user["email"], "changed own password")
            flash("Password changed.")
            return redirect(url_for("profile"))
    return render_template("profile.html", error=error), 400 if error else 200


@app.route("/users", methods=["GET", "POST"])
def users():
    """Admin only: list accounts and create new ones. There is no public
    sign-up; this is a company tool."""
    error = None
    if request.method == "POST":
        f = request.form
        name = f.get("name", "").strip()
        email = f.get("email", "").strip().lower()
        role = f.get("role")
        if not name or "@" not in email:
            error = "Enter a name and a valid email."
        elif role not in db.ROLES:
            error = "Pick a role."
        elif len(f.get("password", "")) < MIN_PASSWORD:
            error = f"The first password must be at least {MIN_PASSWORD} characters."
        else:
            try:
                new_id = db.execute(
                    """INSERT INTO users (name, email, password_hash, role, created_at)
                       VALUES (?,?,?,?,?)""",
                    (name, email, generate_password_hash(f["password"]), role,
                     TODAY.strftime("%Y-%m-%d")),
                )
            except sqlite3.IntegrityError:
                error = f"An account for {email} already exists."
            else:
                db.log(g.user, "user", new_id, email, "created", [("role", "", role)])
                flash(f"Account created for {name}. Give them their first password in person.")
                return redirect(url_for("users"))

    return render_template(
        "users.html",
        users=db.query("SELECT * FROM users ORDER BY name"),
        error=error,
        form=request.form if error else {},
    ), 400 if error else 200


@app.route("/users/<int:user_id>", methods=["POST"])
def user_update(user_id):
    """Admin only: change someone's role or reset their password."""
    user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        abort(404)
    f = request.form

    if f.get("action") == "role":
        if user["id"] == g.user["id"]:
            flash("You cannot change your own role, so there is always an admin.")
        elif f.get("role") in db.ROLES:
            db.execute("UPDATE users SET role = ? WHERE id = ?", (f["role"], user_id))
            db.log_update(g.user, "user", user_id, user["email"], user, {"role": f["role"]})
            flash(f"{user['name']} is now {f['role']}.")
    elif f.get("action") == "password":
        if len(f.get("password", "")) < MIN_PASSWORD:
            flash(f"Not changed: passwords must be at least {MIN_PASSWORD} characters.")
        else:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(f["password"]), user_id),
            )
            db.log(g.user, "user", user_id, user["email"], "reset password")
            flash(f"Password reset for {user['name']}.")
    return redirect(url_for("users"))


# ---------------------------------------------------------------------------
# Comments and evidence files
# ---------------------------------------------------------------------------

COMMENTABLE = {"control": "controls", "risk": "risks", "finding": "findings"}
MAX_COMMENT = 2000


def entity_row(entity_type, entity_id):
    """The control, risk or finding a comment is about, or 404."""
    table = COMMENTABLE.get(entity_type)
    if not table:
        abort(404)
    row = db.query(f"SELECT * FROM {table} WHERE id = ?", (entity_id,), one=True)
    if not row:
        abort(404)
    return row


def entity_page(entity_type, row):
    if entity_type == "control":
        return url_for("control_detail", ref=row["ref"])
    if entity_type == "risk":
        return url_for("risk_form", risk_id=row["id"])
    return url_for("finding_form", finding_id=row["id"])


@app.route("/comments", methods=["POST"])
def comment_add():
    entity_type = request.form.get("entity_type", "")
    row = entity_row(entity_type, parse_int(request.form.get("entity_id")))
    body = request.form.get("body", "").strip()
    if not body:
        flash("Write something before posting a comment.")
    elif len(body) > MAX_COMMENT:
        flash(f"Comments can be at most {MAX_COMMENT} characters.")
    else:
        db.execute(
            """INSERT INTO comments (user_id, user_name, entity_type, entity_id, body, at)
               VALUES (?,?,?,?,?,?)""",
            (g.user["id"], g.user["name"], entity_type, row["id"], body, db.now_utc()),
        )
        db.log(g.user, entity_type, row["id"], row["ref"], "commented",
               [(None, None, body)])
    return redirect(entity_page(entity_type, row) + "#comments")


# What may be uploaded, and the bytes each kind of file must start with, so a
# renamed .exe or .html cannot slip in as "report.pdf". Text files have no
# signature; they are rejected if they contain NUL bytes (i.e. are binary).
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_UPLOADS = {
    "pdf":  ("application/pdf", [b"%PDF-"]),
    "png":  ("image/png",       [b"\x89PNG\r\n\x1a\n"]),
    "jpg":  ("image/jpeg",      [b"\xff\xd8\xff"]),
    "jpeg": ("image/jpeg",      [b"\xff\xd8\xff"]),
    "txt":  ("text/plain",      None),
    "csv":  ("text/csv",        None),
}


def check_upload(filename, data):
    """Return (extension, content type) for an acceptable file, or raise
    ValueError with a message for the user."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_UPLOADS:
        raise ValueError("Only PDF, PNG, JPG, TXT and CSV files can be uploaded.")
    if not data:
        raise ValueError("That file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"That file is too big. The limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    content_type, signatures = ALLOWED_UPLOADS[ext]
    if signatures and not any(data.startswith(sig) for sig in signatures):
        raise ValueError(f"That file does not look like a real .{ext} file.")
    if signatures is None and b"\x00" in data[:8192]:
        raise ValueError(f"That file does not look like a real .{ext} file.")
    return ext, content_type


@app.route("/controls/<ref>/evidence", methods=["POST"])
def evidence_upload(ref):
    control = db.query("SELECT * FROM controls WHERE ref = ?", (ref,), one=True)
    if not control:
        abort(404)
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a file to upload.")
        return redirect(url_for("control_detail", ref=ref) + "#evidence-files")

    data = upload.read()
    try:
        ext, content_type = check_upload(upload.filename, data)
    except ValueError as err:
        flash(str(err))
        return redirect(url_for("control_detail", ref=ref) + "#evidence-files")

    # The file is stored under a random name; the user's own file name is only
    # ever shown, never used as a path.
    stored_name = f"{secrets.token_hex(16)}.{ext}"
    os.makedirs(db.UPLOAD_DIR, exist_ok=True)
    with open(os.path.join(db.UPLOAD_DIR, stored_name), "wb") as fh:
        fh.write(data)

    original = os.path.basename(upload.filename.replace("\\", "/"))[:200]
    db.execute(
        """INSERT INTO evidence_files (control_id, original_name, stored_name, content_type,
           size, uploaded_by, uploaded_by_name, at) VALUES (?,?,?,?,?,?,?,?)""",
        (control["id"], original, stored_name, content_type, len(data),
         g.user["id"], g.user["name"], db.now_utc()),
    )
    db.log(g.user, "control", control["id"], ref, "uploaded evidence", [(None, None, original)])
    flash(f"Uploaded {original}.")
    return redirect(url_for("control_detail", ref=ref) + "#evidence-files")


@app.route("/evidence/<int:file_id>")
def evidence_file(file_id):
    """Open (images, PDFs, text) or download (?download=1, and CSVs) a file.
    Only signed-in users get here; the gatekeeper sees to that."""
    ev = db.query("SELECT * FROM evidence_files WHERE id = ?", (file_id,), one=True)
    if not ev:
        abort(404)
    inline = not request.args.get("download") and ev["content_type"] != "text/csv"
    resp = send_from_directory(
        db.UPLOAD_DIR, ev["stored_name"],
        mimetype=ev["content_type"],
        as_attachment=not inline,
        download_name=ev["original_name"],
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/evidence/<int:file_id>/delete", methods=["POST"])
def evidence_delete(file_id):
    """The person who uploaded a file, or an admin, can remove it."""
    ev = db.query(
        """SELECT e.*, c.ref FROM evidence_files e JOIN controls c ON c.id = e.control_id
           WHERE e.id = ?""",
        (file_id,), one=True,
    )
    if not ev:
        abort(404)
    if g.user["role"] != "admin" and ev["uploaded_by"] != g.user["id"]:
        abort(403)
    db.execute("DELETE FROM evidence_files WHERE id = ?", (file_id,))
    try:
        os.remove(os.path.join(db.UPLOAD_DIR, ev["stored_name"]))
    except FileNotFoundError:
        pass                        # already gone, e.g. a wiped /tmp on Vercel
    db.log(g.user, "control", ev["control_id"], ev["ref"], "deleted evidence",
           [(None, ev["original_name"], None)])
    flash(f"Deleted {ev['original_name']}.")
    return redirect(url_for("control_detail", ref=ev["ref"]) + "#evidence-files")


def parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        abort(404)


# ---------------------------------------------------------------------------
# Delete, archive and bulk actions
# ---------------------------------------------------------------------------

# What can be deleted, and how to describe it on the "are you sure?" page.
DELETABLE = {
    "risk":     ("risks",     "risks",     lambda r: f"{r['ref']}: {r['asset']}"),
    "document": ("documents", "documents", lambda r: f"{r['code']}: {r['title']}"),
    "finding":  ("findings",  "audit",     lambda r: f"{r['ref']}: {r['description']}"),
}


def item_ref(kind, row):
    return row["code"] if kind == "document" else row["ref"]


@app.route("/delete/<kind>/<int:item_id>", methods=["GET", "POST"])
def delete_item(kind, item_id):
    """Admin only. GET shows what will be removed ("are you sure?"); POST
    removes it. The activity history of the item is kept on purpose: an
    audit trail that loses entries when records are deleted is no trail."""
    if kind not in DELETABLE:
        abort(404)
    table, list_endpoint, describe = DELETABLE[kind]
    row = db.query(f"SELECT * FROM {table} WHERE id = ?", (item_id,), one=True)
    if not row:
        abort(404)

    comments = db.query(
        "SELECT COUNT(*) c FROM comments WHERE entity_type = ? AND entity_id = ?",
        (kind, item_id), one=True,
    )["c"]
    links = 0
    if kind == "risk":
        links = len(linked_control_refs(item_id))
    elif kind == "document":
        links = db.query("SELECT COUNT(*) c FROM doc_controls WHERE document_id = ?",
                         (item_id,), one=True)["c"]

    if request.method == "POST":
        db.execute(f"DELETE FROM {table} WHERE id = ?", (item_id,))   # links cascade
        db.execute("DELETE FROM comments WHERE entity_type = ? AND entity_id = ?",
                   (kind, item_id))
        db.log(g.user, kind, item_id, item_ref(kind, row), "deleted",
               [(None, describe(row), None)])
        if kind in ("risk", "document"):
            db.refresh_justifications()
        flash(f"Deleted {item_ref(kind, row)}.")
        return redirect(url_for(list_endpoint))

    return render_template(
        "confirm_delete.html",
        kind=kind, row=row, ref=item_ref(kind, row), description=describe(row),
        comments=comments, links=links, back=url_for(list_endpoint),
    )


@app.route("/documents/<int:doc_id>/archive", methods=["POST"])
def document_archive(doc_id):
    """Retire a document without losing it: status becomes Obsolete, it drops
    out of the register's default view and out of the approval percentage."""
    doc = db.query("SELECT * FROM documents WHERE id = ?", (doc_id,), one=True)
    if not doc:
        abort(404)
    if doc["status"] != "Obsolete":
        db.execute("UPDATE documents SET status = 'Obsolete' WHERE id = ?", (doc_id,))
        db.log_update(g.user, "document", doc_id, doc["code"], doc, {"status": "Obsolete"})
        flash(f"Archived {doc['code']}. It is kept, marked Obsolete.")
    return redirect(url_for("documents"))


@app.route("/controls/bulk", methods=["POST"])
def controls_bulk():
    """Set the status of several ticked controls at once."""
    status = request.form.get("status")
    refs = request.form.getlist("refs")
    back = safe_next(request.form.get("back"))
    if status not in db.CONTROL_STATUSES:
        flash("Pick the status to apply.")
        return redirect(back)
    if not refs:
        flash("Tick at least one control first.")
        return redirect(back)

    changed = 0
    for ref in refs:
        c = db.query("SELECT * FROM controls WHERE ref = ? AND applicable = 1", (ref,), one=True)
        if not c or c["status"] == status:
            continue
        db.execute("UPDATE controls SET status = ?, updated_at = ? WHERE id = ?",
                   (status, TODAY.strftime("%Y-%m-%d"), c["id"]))
        db.log_update(g.user, "control", c["id"], ref, c, {"status": status})
        changed += 1
    skipped = len(refs) - changed
    msg = f"Set {changed} control{'s' if changed != 1 else ''} to {status}."
    if skipped:
        msg += f" {skipped} skipped (already {status}, or excluded)."
    flash(msg)
    return redirect(back)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    stats = db.readiness()
    db.snapshot_readiness(stats)

    overdue_findings = db.query(
        """SELECT * FROM findings
           WHERE status != 'Closed' AND due_date < ?
           ORDER BY due_date""",
        (TODAY.strftime("%Y-%m-%d"),),
    )

    top_risks = db.query(
        """SELECT *,
                  COALESCE(res_likelihood, likelihood) * COALESCE(res_impact, impact) AS score
           FROM risks
           WHERE status != 'Closed'
           ORDER BY score DESC, ref
           LIMIT 6"""
    )

    upcoming_reviews = db.query(
        """SELECT * FROM documents
           WHERE next_review IS NOT NULL AND status = 'Approved'
           ORDER BY next_review
           LIMIT 5"""
    )

    blocking = db.query(
        """SELECT ref, title, status FROM clauses
           WHERE status IN ('Not Started', 'In Progress')
           ORDER BY ref"""
    )

    return render_template(
        "dashboard.html",
        stats=stats,
        themes=db.theme_stats(),
        top_risks=top_risks,
        overdue_findings=overdue_findings,
        upcoming_reviews=upcoming_reviews,
        blocking=blocking,
        activity=db.recent_activity(8),
        trend=trend_chart(db.readiness_history()),
    )


def trend_chart(rows, width=900, height=230, left=40, right=56, top=14, bottom=28):
    """Geometry for the hand-drawn "readiness over time" SVG line chart.
    y runs 0-100% (a percentage always starts at zero); x spaces the readings
    evenly, oldest on the left."""
    plot_w, plot_h = width - left - right, height - top - bottom
    n = len(rows)
    step = plot_w / (n - 1) if n > 1 else 0
    points = []
    for i, r in enumerate(rows):
        x = left + (i * step if n > 1 else plot_w / 2)
        y = top + plot_h * (1 - max(0, min(100, r["overall"])) / 100)
        day = datetime.strptime(r["day"], "%Y-%m-%d")
        points.append({
            "x": round(x, 1), "y": round(y, 1), "overall": r["overall"],
            "controls": r["controls"], "clauses": r["clauses"], "documents": r["documents"],
            "day": r["day"], "label": day.strftime("%d %b").lstrip("0"),
            "long": day.strftime("%d %B %Y").lstrip("0"),
        })
    return {
        "width": width, "height": height, "left": left, "right": width - right,
        "top": top, "baseline": top + plot_h,
        "band": step or plot_w,             # hover strip width per reading
        "grid": [{"y": round(top + plot_h * (1 - v / 100), 1), "label": f"{v}%"}
                 for v in (0, 25, 50, 75, 100)],
        "points": points,
        "path": " ".join(f"{'M' if i == 0 else 'L'}{p['x']},{p['y']}"
                         for i, p in enumerate(points)),
    }


@app.route("/my-tasks")
def my_tasks():
    """Everything assigned to one person. Defaults to me; ?user= shows a
    colleague's list, so the compliance lead can check who is overloaded."""
    person = g.user
    if request.args.get("user"):
        person = db.query("SELECT * FROM users WHERE id = ?",
                          (parse_assignee(request.args["user"]),), one=True) or g.user
    tasks = db.open_tasks(person["id"])
    return render_template(
        "my_tasks.html",
        person=person,
        tasks=tasks,
        overdue_refs={t["ref"] for t in db.overdue(tasks)},
        task_url=task_url,
    )


@app.route("/activity")
def activity():
    """Everything anyone changed, newest first."""
    return render_template("activity.html", activity=db.recent_activity(300))


# ---------------------------------------------------------------------------
# Annex A controls
# ---------------------------------------------------------------------------

@app.route("/controls")
def controls():
    theme = request.args.get("theme", "")
    status = request.args.get("status", "")
    search = request.args.get("q", "").strip()

    sql = "SELECT * FROM controls WHERE 1=1"
    args = []
    if theme:
        sql += " AND theme = ?"
        args.append(theme)
    if status:
        sql += " AND status = ?"
        args.append(status)
    if search:
        sql += " AND (title LIKE ? OR ref LIKE ? OR purpose LIKE ?)"
        args += [f"%{search}%"] * 3
    sql += " ORDER BY CAST(SUBSTR(ref, 3, 1) AS INTEGER), CAST(SUBSTR(ref, 5) AS INTEGER)"

    return render_template(
        "controls.html",
        controls=db.query(sql, args),
        themes=db.THEMES,
        statuses=db.CONTROL_STATUSES,
        sel_theme=theme,
        sel_status=status,
        search=search,
        stats=db.control_stats(),
    )


@app.route("/controls/<ref>", methods=["GET", "POST"])
def control_detail(ref):
    control = db.query("SELECT * FROM controls WHERE ref = ?", (ref,), one=True)
    if not control:
        return "Control not found", 404

    if request.method == "POST":
        new = {
            "status": request.form["status"],
            "owner": request.form["owner"],
            "applicable": 1 if request.form.get("applicable") == "1" else 0,
            "justification": request.form["justification"],
            "evidence": request.form["evidence"],
            "notes": request.form["notes"],
            "assignee_id": parse_assignee(request.form.get("assignee_id")),
            "due_date": parse_date(request.form.get("due_date")),
        }
        db.execute(
            """UPDATE controls
               SET status = ?, owner = ?, applicable = ?, justification = ?,
                   evidence = ?, notes = ?, assignee_id = ?, due_date = ?,
                   updated_at = ?
               WHERE ref = ?""",
            tuple(new.values()) + (TODAY.strftime("%Y-%m-%d"), ref),
        )
        db.log_update(g.user, "control", control["id"], ref, control, new)
        db.refresh_justifications()
        return redirect(url_for("control_detail", ref=ref))

    linked_risks = db.query(
        """SELECT r.* FROM risks r
           JOIN risk_controls rc ON rc.risk_id = r.id
           WHERE rc.control_id = ?
           ORDER BY r.ref""",
        (control["id"],),
    )
    linked_docs = db.query(
        """SELECT d.* FROM documents d
           JOIN doc_controls dc ON dc.document_id = d.id
           WHERE dc.control_id = ?
           ORDER BY d.code""",
        (control["id"],),
    )
    findings = db.query(
        "SELECT * FROM findings WHERE clause_or_control = ? ORDER BY ref", (ref,)
    )

    return render_template(
        "control_detail.html",
        c=control,
        statuses=db.CONTROL_STATUSES,
        linked_risks=linked_risks,
        linked_docs=linked_docs,
        findings=findings,
        history=db.history("control", control["id"]),
        comments=db.comments_for("control", control["id"]),
        evidence=db.evidence_for(control["id"]),
    )


# ---------------------------------------------------------------------------
# ISMS clauses 4-10
# ---------------------------------------------------------------------------

@app.route("/clauses", methods=["GET", "POST"])
def clauses():
    if request.method == "POST":
        clause = db.query("SELECT * FROM clauses WHERE ref = ?", (request.form["ref"],), one=True)
        if not clause:
            abort(404)
        new = {"status": request.form["status"], "notes": request.form.get("notes", "")}
        db.execute(
            "UPDATE clauses SET status = ?, notes = ? WHERE ref = ?",
            (new["status"], new["notes"], clause["ref"]),
        )
        db.log_update(g.user, "clause", clause["id"], clause["ref"], clause, new)
        return redirect(url_for("clauses"))

    return render_template(
        "clauses.html",
        clauses=db.query("SELECT * FROM clauses ORDER BY id"),
        statuses=db.CLAUSE_STATUSES,
        stats=db.clause_stats(),
    )


# ---------------------------------------------------------------------------
# Risk register
# ---------------------------------------------------------------------------

@app.route("/risks")
def risks():
    status = request.args.get("status", "")
    sql = "SELECT * FROM risks"
    args = []
    if status:
        sql += " WHERE status = ?"
        args.append(status)
    sql += """ ORDER BY COALESCE(res_likelihood, likelihood) *
                        COALESCE(res_impact, impact) DESC, ref"""

    return render_template(
        "risks.html",
        risks=db.query(sql, args),
        stats=db.risk_stats(),
        statuses=db.RISK_STATUSES,
        sel_status=status,
        matrix=risk_matrix(),
    )


def risk_matrix():
    """Build the 5x5 heat map, counting open risks at each L/I position."""
    grid = {(l, i): [] for l in range(1, 6) for i in range(1, 6)}
    for r in db.query("SELECT * FROM risks WHERE status != 'Closed'"):
        lk = r["res_likelihood"] or r["likelihood"]
        im = r["res_impact"] or r["impact"]
        grid[(lk, im)].append(r["ref"])
    return grid


@app.route("/risks/new", methods=["GET", "POST"])
@app.route("/risks/<int:risk_id>", methods=["GET", "POST"])
def risk_form(risk_id=None):
    risk = None
    if risk_id:
        risk = db.query("SELECT * FROM risks WHERE id = ?", (risk_id,), one=True)
        if not risk:
            return "Risk not found", 404

    error = None
    if request.method == "POST":
        f = request.form
        likelihood, impact = score_1_to_5(f.get("likelihood")), score_1_to_5(f.get("impact"))
        res_likelihood = score_1_to_5(f.get("res_likelihood"), optional=True)
        res_impact = score_1_to_5(f.get("res_impact"), optional=True)
        if None in (likelihood, impact) or False in (res_likelihood, res_impact):
            error = "Likelihood and impact must be whole numbers from 1 to 5."

    # "Duplicate": /risks/new?from=<id> opens a new-risk form filled in from an
    # existing risk. Nothing is saved until the user presses Create.
    copied_from = None
    if not risk and request.args.get("from"):
        copied_from = db.query("SELECT * FROM risks WHERE id = ?",
                               (parse_int(request.args["from"]),), one=True)

    if risk:
        linked = linked_control_refs(risk_id)
    elif copied_from:
        linked = linked_control_refs(copied_from["id"])
    else:
        linked = []

    if request.method == "POST" and not error:
        new = {
            "asset": f["asset"], "asset_type": f["asset_type"], "threat": f["threat"],
            "vulnerability": f["vulnerability"], "existing_controls": f["existing_controls"],
            "likelihood": likelihood, "impact": impact,
            "treatment": f["treatment"], "treatment_plan": f["treatment_plan"],
            "res_likelihood": res_likelihood, "res_impact": res_impact,
            "owner": f["owner"], "target_date": f["target_date"], "status": f["status"],
            "assignee_id": parse_assignee(f.get("assignee_id")),
        }
        fields = tuple(new.values())
        if risk:
            db.execute(
                """UPDATE risks SET asset=?, asset_type=?, threat=?, vulnerability=?,
                   existing_controls=?, likelihood=?, impact=?, treatment=?,
                   treatment_plan=?, res_likelihood=?, res_impact=?, owner=?,
                   target_date=?, status=?, assignee_id=? WHERE id=?""",
                fields + (risk_id,),
            )
            new_id, ref = risk_id, risk["ref"]
        else:
            last = db.query("SELECT ref FROM risks ORDER BY id DESC LIMIT 1", one=True)
            nxt = int(last["ref"].split("-")[1]) + 1 if last else 1
            ref = f"R-{nxt:03d}"
            new_id = db.execute(
                """INSERT INTO risks (ref, asset, asset_type, threat, vulnerability,
                   existing_controls, likelihood, impact, treatment, treatment_plan,
                   res_likelihood, res_impact, owner, target_date, status, assignee_id,
                   created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ref,) + fields + (TODAY.strftime("%Y-%m-%d"),),
            )

        # Rebuild the control links from the submitted checkboxes.
        db.execute("DELETE FROM risk_controls WHERE risk_id = ?", (new_id,))
        for cref in request.form.getlist("controls"):
            ctl = db.query("SELECT id FROM controls WHERE ref = ?", (cref,), one=True)
            if ctl:
                db.execute(
                    "INSERT OR IGNORE INTO risk_controls (risk_id, control_id) VALUES (?,?)",
                    (new_id, ctl["id"]),
                )

        now_linked = ", ".join(sorted(linked_control_refs(new_id)))
        if risk:
            new["controls"] = now_linked
            db.log_update(g.user, "risk", new_id, ref,
                          {**dict(risk), "controls": ", ".join(sorted(linked))}, new)
        else:
            db.log(g.user, "risk", new_id, ref, "created")
        db.refresh_justifications()
        return redirect(url_for("risks"))

    prefill = None
    if copied_from:
        prefill = {**dict(copied_from), "id": None, "ref": None, "status": "Open"}

    return render_template(
        "risk_form.html",
        risk=risk or prefill,
        copied_from=copied_from,
        linked=linked,
        all_controls=db.query("SELECT ref, title, theme FROM controls WHERE applicable = 1 ORDER BY id"),
        treatments=db.RISK_TREATMENTS,
        statuses=db.RISK_STATUSES,
        asset_types=db.ASSET_TYPES,
        error=error,
        history=db.history("risk", risk_id) if risk else [],
        comments=db.comments_for("risk", risk_id) if risk else [],
    ), 400 if error else 200


def linked_control_refs(risk_id):
    return [
        r["ref"]
        for r in db.query(
            """SELECT c.ref FROM controls c
               JOIN risk_controls rc ON rc.control_id = c.id
               WHERE rc.risk_id = ?""",
            (risk_id,),
        )
    ]


def score_1_to_5(value, optional=False):
    """Parse a likelihood or impact score.

    Returns the int if it is 1-5. A blank optional value (residual scores)
    returns None; anything else invalid returns None for a required score and
    False for an optional one, so the caller can tell blank from bad.
    """
    if optional and not value:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return False if optional else None
    if 1 <= n <= 5:
        return n
    return False if optional else None


# ---------------------------------------------------------------------------
# Document register
# ---------------------------------------------------------------------------

@app.route("/documents")
def documents():
    show_archived = bool(request.args.get("archived"))
    sql = "SELECT * FROM documents"
    if not show_archived:
        sql += " WHERE status != 'Obsolete'"
    docs = db.query(sql + " ORDER BY code")
    return render_template(
        "documents.html", documents=docs, stats=db.document_stats(),
        show_archived=show_archived,
    )


@app.route("/documents/new", methods=["GET", "POST"])
@app.route("/documents/<int:doc_id>", methods=["GET", "POST"])
def document_form(doc_id=None):
    doc = None
    if doc_id:
        doc = db.query("SELECT * FROM documents WHERE id = ?", (doc_id,), one=True)
        if not doc:
            return "Document not found", 404

    error = None
    if request.method == "POST":
        f = request.form
        new = {
            "code": f["code"], "title": f["title"], "doc_type": f["doc_type"],
            "version": f["version"], "owner": f["owner"], "status": f["status"],
            "approved_on": f.get("approved_on") or None,
            "next_review": f.get("next_review") or None,
            "clause_ref": f.get("clause_ref") or None, "notes": f.get("notes", ""),
        }
        fields = tuple(new.values())
        try:
            if doc:
                db.execute(
                    """UPDATE documents SET code=?, title=?, doc_type=?, version=?, owner=?,
                       status=?, approved_on=?, next_review=?, clause_ref=?, notes=?
                       WHERE id=?""",
                    fields + (doc_id,),
                )
            else:
                new_id = db.execute(
                    """INSERT INTO documents (code, title, doc_type, version, owner, status,
                       approved_on, next_review, clause_ref, notes)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    fields,
                )
        except sqlite3.IntegrityError:
            error = f"A document with the code {f['code']} already exists. Choose a different code."
            # Keep what the user typed so they only have to fix the code.
            doc = {**(dict(doc) if doc else {}), **f.to_dict()}
        else:
            if doc:
                db.log_update(g.user, "document", doc_id, new["code"], doc, new)
            else:
                db.log(g.user, "document", new_id, new["code"], "created")
            db.refresh_justifications()
            return redirect(url_for("documents"))

    return render_template(
        "document_form.html",
        doc=doc,
        doc_types=db.DOC_TYPES,
        statuses=db.DOC_STATUSES,
        error=error,
        history=db.history("document", doc_id) if doc_id else [],
    ), 400 if error else 200


# ---------------------------------------------------------------------------
# Statement of Applicability - the central certification deliverable
# ---------------------------------------------------------------------------

@app.route("/soa")
def soa():
    rows = db.query(
        """SELECT * FROM controls
           ORDER BY CAST(SUBSTR(ref, 3, 1) AS INTEGER), CAST(SUBSTR(ref, 5) AS INTEGER)"""
    )
    return render_template("soa.html", controls=rows, stats=db.control_stats())


def csv_cell(value):
    """Stop a spreadsheet from running text that looks like a formula: a
    risk titled '=HYPERLINK(...)' must open as text, not as a live link."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return "" if value is None else value


def csv_response(filename, title, header, rows):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([title])
    writer.writerow([f"Generated {TODAY.strftime('%d %B %Y')}"])
    writer.writerow([])
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_cell(v) for v in row])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# Registers that can be downloaded as CSV, beyond the SoA.
EXPORTS = {
    "risks": ("risk_register.csv", "Risk register - ISO/IEC 27001:2022", """
        SELECT r.ref, r.asset, r.asset_type, r.threat, r.vulnerability, r.existing_controls,
               r.likelihood, r.impact, r.likelihood * r.impact AS inherent_score,
               r.treatment, r.treatment_plan, r.res_likelihood, r.res_impact,
               r.res_likelihood * r.res_impact AS residual_score,
               r.owner, u.name AS assigned_to, r.target_date, r.status,
               (SELECT GROUP_CONCAT(c.ref, '; ') FROM risk_controls rc
                  JOIN controls c ON c.id = rc.control_id
                 WHERE rc.risk_id = r.id) AS controls
          FROM risks r LEFT JOIN users u ON u.id = r.assignee_id
         ORDER BY r.ref"""),
    "documents": ("document_register.csv", "Document register - ISO/IEC 27001:2022", """
        SELECT code, title, doc_type AS type, version, owner, status, approved_on,
               next_review, clause_ref AS clause, notes
          FROM documents ORDER BY code"""),
    "findings": ("audit_findings.csv", "Audit findings and corrective action - ISO/IEC 27001:2022", """
        SELECT f.ref, f.source, f.raised_on, f.clause_or_control, f.description, f.severity,
               f.root_cause, f.corrective_action, f.owner, u.name AS assigned_to,
               f.due_date, f.status, f.closed_on
          FROM findings f LEFT JOIN users u ON u.id = f.assignee_id
         ORDER BY f.ref"""),
}


@app.route("/export/<kind>.csv")
def export_csv(kind):
    if kind not in EXPORTS:
        abort(404)
    filename, title, sql = EXPORTS[kind]
    columns, rows = db.query_table(sql)
    header = [c.replace("_", " ").capitalize() for c in columns]
    return csv_response(filename, title, header, rows)


# ---------------------------------------------------------------------------
# Search across every register
# ---------------------------------------------------------------------------

def like_pattern(text):
    """'%text%' with LIKE's own wildcards in the text treated literally."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


SEARCHES = [
    # (heading, SQL returning id/ref/title/status, columns searched, link)
    ("Controls", "SELECT id, ref, title, status FROM controls",
     ["ref", "title", "purpose", "owner", "evidence", "notes", "justification"],
     lambda r: url_for("control_detail", ref=r["ref"])),
    ("Risks", "SELECT id, ref, asset || ': ' || COALESCE(threat, '') AS title, status FROM risks",
     ["ref", "asset", "threat", "vulnerability", "owner", "treatment_plan"],
     lambda r: url_for("risk_form", risk_id=r["id"])),
    ("Documents", "SELECT id, code AS ref, title, status FROM documents",
     ["code", "title", "owner", "notes"],
     lambda r: url_for("document_form", doc_id=r["id"])),
    ("Findings", "SELECT id, ref, description AS title, status FROM findings",
     ["ref", "description", "clause_or_control", "corrective_action", "owner"],
     lambda r: url_for("finding_form", finding_id=r["id"])),
]
SEARCH_LIMIT = 50


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()[:100]
    groups = []
    if len(q) >= 2:
        pattern = like_pattern(q)
        for heading, select, columns, link in SEARCHES:
            where = " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in columns)
            rows = db.query(f"{select} WHERE {where} ORDER BY ref LIMIT ?",
                            [pattern] * len(columns) + [SEARCH_LIMIT + 1])
            groups.append({
                "heading": heading,
                "items": [{**dict(r), "url": link(r)} for r in rows[:SEARCH_LIMIT]],
                "more": len(rows) > SEARCH_LIMIT,
            })
    return render_template("search.html", q=q, groups=groups,
                           total=sum(len(g["items"]) for g in groups))


@app.route("/soa/export.csv")
def soa_export():
    """Export the Statement of Applicability in the layout an auditor expects."""
    rows = db.query(
        """SELECT c.ref, c.theme, c.title, c.control_type, c.applicable,
                  c.justification, c.status, c.owner, c.evidence,
                  (SELECT GROUP_CONCAT(d.code, '; ') FROM documents d
                     JOIN doc_controls dc ON dc.document_id = d.id
                    WHERE dc.control_id = c.id) AS docs
           FROM controls c
           ORDER BY CAST(SUBSTR(c.ref, 3, 1) AS INTEGER),
                    CAST(SUBSTR(c.ref, 5) AS INTEGER)"""
    )

    return csv_response(
        "statement_of_applicability.csv",
        "Statement of Applicability - ISO/IEC 27001:2022",
        ["Control", "Theme", "Control name", "Type", "Applicable",
         "Justification", "Implementation status", "Owner",
         "Supporting documents", "Evidence"],
        [[r["ref"], r["theme"], r["title"], r["control_type"],
          "Yes" if r["applicable"] else "No",
          r["justification"], r["status"], r["owner"],
          r["docs"] or "", r["evidence"] or ""] for r in rows],
    )


# ---------------------------------------------------------------------------
# Internal audit findings and corrective action
# ---------------------------------------------------------------------------

@app.route("/audit")
def audit():
    return render_template(
        "audit.html",
        findings=db.query(
            """SELECT * FROM findings
               ORDER BY CASE status WHEN 'Open' THEN 0 WHEN 'In Progress' THEN 1 ELSE 2 END,
                        CASE severity WHEN 'Major' THEN 0 WHEN 'Minor' THEN 1
                                      WHEN 'Observation' THEN 2 ELSE 3 END,
                        ref"""
        ),
        stats=db.finding_stats(),
    )


@app.route("/audit/new", methods=["GET", "POST"])
@app.route("/audit/<int:finding_id>", methods=["GET", "POST"])
def finding_form(finding_id=None):
    finding = None
    if finding_id:
        finding = db.query("SELECT * FROM findings WHERE id = ?", (finding_id,), one=True)
        if not finding:
            return "Finding not found", 404

    if request.method == "POST":
        f = request.form
        closed_on = f.get("closed_on") or (
            TODAY.strftime("%Y-%m-%d") if f["status"] == "Closed" else None
        )
        new = {
            "source": f["source"], "raised_on": f["raised_on"],
            "clause_or_control": f["clause_or_control"], "description": f["description"],
            "severity": f["severity"], "root_cause": f["root_cause"],
            "corrective_action": f["corrective_action"], "owner": f["owner"],
            "due_date": f["due_date"], "status": f["status"], "closed_on": closed_on,
            "assignee_id": parse_assignee(f.get("assignee_id")),
        }
        fields = tuple(new.values())
        if finding:
            db.execute(
                """UPDATE findings SET source=?, raised_on=?, clause_or_control=?,
                   description=?, severity=?, root_cause=?, corrective_action=?,
                   owner=?, due_date=?, status=?, closed_on=?, assignee_id=? WHERE id=?""",
                fields + (finding_id,),
            )
            db.log_update(g.user, "finding", finding_id, finding["ref"], finding, new)
        else:
            last = db.query("SELECT ref FROM findings ORDER BY id DESC LIMIT 1", one=True)
            nxt = int(last["ref"].split("-")[1]) + 1 if last else 1
            ref = f"NC-{nxt:03d}"
            new_id = db.execute(
                """INSERT INTO findings (ref, source, raised_on, clause_or_control,
                   description, severity, root_cause, corrective_action, owner,
                   due_date, status, closed_on, assignee_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ref,) + fields,
            )
            db.log(g.user, "finding", new_id, ref, "created")
        return redirect(url_for("audit"))

    return render_template(
        "finding_form.html",
        f=finding,
        severities=db.FINDING_SEVERITIES,
        statuses=db.FINDING_STATUSES,
        sources=db.FINDING_SOURCES,
        history=db.history("finding", finding_id) if finding else [],
        comments=db.comments_for("finding", finding_id) if finding else [],
    )


# ---------------------------------------------------------------------------
# Gap analysis - what still blocks certification
# ---------------------------------------------------------------------------

@app.route("/gap")
def gap():
    not_started = db.query(
        """SELECT * FROM controls
           WHERE applicable = 1 AND status = 'Not Started'
           ORDER BY theme, id"""
    )
    in_progress = db.query(
        """SELECT * FROM controls
           WHERE applicable = 1 AND status = 'In Progress'
           ORDER BY theme, id"""
    )
    unverified = db.query(
        """SELECT * FROM controls
           WHERE applicable = 1 AND status = 'Implemented'
           ORDER BY theme, id"""
    )
    clause_gaps = db.query(
        "SELECT * FROM clauses WHERE status != 'Verified' ORDER BY id"
    )
    unapproved = db.query(
        "SELECT * FROM documents WHERE status IN ('Draft','Under Review') ORDER BY code"
    )
    major = db.query(
        "SELECT * FROM findings WHERE status != 'Closed' AND severity = 'Major' ORDER BY ref"
    )
    high_risks = db.query(
        """SELECT * FROM (
               SELECT *,
                      COALESCE(res_likelihood, likelihood) *
                      COALESCE(res_impact, impact) AS score
               FROM risks
               WHERE status != 'Closed'
           )
           WHERE score >= 10
           ORDER BY score DESC"""
    )
    uncovered = db.query(
        """SELECT c.* FROM controls c
           LEFT JOIN doc_controls dc ON dc.control_id = c.id
           WHERE c.applicable = 1 AND dc.control_id IS NULL
             AND c.status IN ('Implemented', 'Verified')
           ORDER BY c.id"""
    )

    return render_template(
        "gap.html",
        stats=db.readiness(),
        not_started=not_started,
        in_progress=in_progress,
        unverified=unverified,
        clause_gaps=clause_gaps,
        unapproved=unapproved,
        major=major,
        high_risks=high_risks,
        uncovered=uncovered,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
