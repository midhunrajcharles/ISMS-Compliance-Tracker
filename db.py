"""Database access layer for the ISMS Compliance Tracker.

Uses the Python standard library sqlite3 module directly rather than an ORM,
so the SQL behind every screen stays visible and inspectable.
"""

import os
import sqlite3
from datetime import date, datetime, timezone

# The demo is pinned to the last day of the internship so overdue dates and
# review deadlines in the seed data always read the same way. Everything that
# needs "today" imports it from here.
TODAY = date(2025, 1, 23)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "isms.db")
if os.environ.get("ISMS_DB_PATH"):
    DB_PATH = os.environ["ISMS_DB_PATH"]
elif os.environ.get("VERCEL"):
    DB_PATH = "/tmp/isms.db"
else:
    DB_PATH = DEFAULT_DB_PATH
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

# Uploaded evidence files. On Vercel only /tmp is writable, and it is wiped
# on every cold start, so uploads there are temporary.
if os.environ.get("ISMS_UPLOAD_DIR"):
    UPLOAD_DIR = os.environ["ISMS_UPLOAD_DIR"]
elif os.environ.get("VERCEL"):
    UPLOAD_DIR = "/tmp/uploads"
else:
    UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
UPLOADS_ARE_TEMPORARY = bool(os.environ.get("VERCEL"))

# ---------------------------------------------------------------------------
# Domain vocabulary
# ---------------------------------------------------------------------------

CONTROL_STATUSES = ["Not Started", "In Progress", "Implemented", "Verified"]
CLAUSE_STATUSES = CONTROL_STATUSES
DOC_STATUSES = ["Draft", "Under Review", "Approved", "Obsolete"]
DOC_TYPES = ["Policy", "Procedure", "Plan", "Register", "Record"]
RISK_TREATMENTS = ["Modify", "Retain", "Avoid", "Share"]
RISK_STATUSES = ["Open", "In Treatment", "Closed"]
FINDING_SEVERITIES = ["Major", "Minor", "Observation", "OFI"]
FINDING_STATUSES = ["Open", "In Progress", "Closed"]
FINDING_SOURCES = ["Internal Audit", "Management Review", "Incident", "Gap Assessment"]
ASSET_TYPES = ["Information", "Software", "Hardware", "Service", "People"]
THEMES = ["Organizational", "People", "Physical", "Technological"]

# Weight given to each implementation status when scoring readiness. A control
# that is merely "Implemented" is not yet audit-proof; only one that has been
# independently verified counts in full.
STATUS_WEIGHT = {
    "Not Started": 0.0,
    "In Progress": 0.4,
    "Implemented": 0.8,
    "Verified": 1.0,
}

# Overall certification readiness is a weighted blend of the three work
# streams an auditor actually examines.
READINESS_WEIGHTS = {"controls": 0.60, "clauses": 0.20, "documents": 0.20}


# ---------------------------------------------------------------------------
# Connection handling
# ---------------------------------------------------------------------------

def connect():
    """Open a connection with row access by column name and FKs enforced."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def query(sql, args=(), one=False):
    conn = connect()
    try:
        cur = conn.execute(sql, args)
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()


def query_table(sql, args=()):
    """Rows plus column names, so an export has headers even when empty."""
    conn = connect()
    try:
        cur = conn.execute(sql, args)
        return [d[0] for d in cur.description], cur.fetchall()
    finally:
        conn.close()


def execute(sql, args=()):
    """Run a write statement and return the last inserted row id."""
    conn = connect()
    try:
        cur = conn.execute(sql, args)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Users and roles
# ---------------------------------------------------------------------------

# Who may do what. Every signed-in user can read everything; the role only
# decides what they may change.
ROLES = {
    "admin":   "Everything, including creating accounts",
    "editor":  "Add and edit controls, risks, documents and findings",
    "auditor": "Read everything; raise and update audit findings only",
    "viewer":  "Read only, e.g. the external certification auditor",
}

# Created apart from schema.sql, with IF NOT EXISTS, so a database built
# before these features existed gains the tables on the next start without a
# re-seed.
USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE,          -- stored lower-case
    password_hash TEXT    NOT NULL,                 -- werkzeug scrypt hash
    role          TEXT    NOT NULL DEFAULT 'viewer',-- admin|editor|auditor|viewer
    created_at    TEXT    NOT NULL
)
"""

# Who changed what, and when. One row per changed field, so the history of a
# control reads like an audit trail: "status: In Progress -> Verified".
# user_name is copied in so the trail still reads correctly if the account
# is later renamed or removed.
ACTIVITY_SQL = """
CREATE TABLE IF NOT EXISTS activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    user_name   TEXT    NOT NULL,
    entity_type TEXT    NOT NULL,                   -- control|clause|risk|document|finding|user
    entity_id   INTEGER,
    entity_ref  TEXT    NOT NULL,                   -- 'A.8.13', 'R-004', 'ISMS-POL-01'
    action      TEXT    NOT NULL,                   -- created|updated|reset password|...
    field       TEXT,
    old_value   TEXT,
    new_value   TEXT,
    at          TEXT    NOT NULL                    -- real UTC time, 'YYYY-MM-DD HH:MM:SS'
);
CREATE INDEX IF NOT EXISTS idx_activity_entity ON activity(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_activity_at     ON activity(at);
"""

# Discussion on a control, risk or finding ("Waiting on IT for the backup test").
COMMENTS_SQL = """
CREATE TABLE IF NOT EXISTS comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    user_name   TEXT    NOT NULL,
    entity_type TEXT    NOT NULL,                   -- control|risk|finding
    entity_id   INTEGER NOT NULL,
    body        TEXT    NOT NULL,
    at          TEXT    NOT NULL                    -- real UTC time
);
CREATE INDEX IF NOT EXISTS idx_comments_entity ON comments(entity_type, entity_id);
"""

# One readiness reading per real calendar day, for the "readiness over time"
# chart. Written when the dashboard is viewed; a later view the same day
# replaces that day's reading.
SNAPSHOTS_SQL = """
CREATE TABLE IF NOT EXISTS readiness_snapshots (
    day       TEXT PRIMARY KEY,                     -- real date, 'YYYY-MM-DD'
    overall   REAL NOT NULL,
    controls  REAL NOT NULL,
    clauses   REAL NOT NULL,
    documents REAL NOT NULL
);
"""

# Proof that a control operates. The file itself sits in UPLOAD_DIR under a
# random stored_name; the name the user gave it is only ever displayed.
EVIDENCE_SQL = """
CREATE TABLE IF NOT EXISTS evidence_files (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id       INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    original_name    TEXT    NOT NULL,
    stored_name      TEXT    NOT NULL UNIQUE,
    content_type     TEXT    NOT NULL,
    size             INTEGER NOT NULL,
    uploaded_by      INTEGER,
    uploaded_by_name TEXT    NOT NULL,
    at               TEXT    NOT NULL               -- real UTC time
);
CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence_files(control_id);
"""

# Columns added after the first release, as (table, column, definition).
# ensure_tables() adds any that an older database is missing, so upgrading
# never needs a re-seed. schema.sql has them too, for new databases.
#
# assignee_id is the *person* doing the work. The existing `owner` text stays:
# ISO 27001 lets an owner be a role ("IT Infrastructure Lead"), and the
# accountable role and the person tagged with the task are not always the same.
ADDED_COLUMNS = [
    ("controls", "assignee_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("controls", "due_date",    "TEXT"),
    ("risks",    "assignee_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("findings", "assignee_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
]

# One account per role so every permission level can be shown in a demo.
# Change these passwords (or delete the accounts) before any real use.
DEMO_USERS = [
    ("ISMS Admin",       "admin@example.com",   "admin123", "admin"),
    ("Ravi (IT)",        "editor@example.com",  "demo1234", "editor"),
    ("Internal Auditor", "auditor@example.com", "demo1234", "auditor"),
    ("External Auditor", "viewer@example.com",  "demo1234", "viewer"),
]


def ensure_tables(conn=None):
    """Create the users and activity tables if missing, and add the demo
    accounts if there are no users yet."""
    from werkzeug.security import generate_password_hash

    own_conn = conn is None
    if own_conn:
        conn = connect()
    try:
        conn.execute(USERS_SQL)
        conn.executescript(ACTIVITY_SQL)
        conn.executescript(COMMENTS_SQL)
        conn.executescript(EVIDENCE_SQL)
        conn.executescript(SNAPSHOTS_SQL)
        for table, column, definition in ADDED_COLUMNS:
            existing = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            for name, email, password, role in DEMO_USERS:
                conn.execute(
                    """INSERT INTO users (name, email, password_hash, role, created_at)
                       VALUES (?,?,?,?,?)""",
                    (name, email, generate_password_hash(password), role,
                     TODAY.strftime("%Y-%m-%d")),
                )
        conn.commit()
    finally:
        if own_conn:
            conn.close()


# ---------------------------------------------------------------------------
# Activity history
# ---------------------------------------------------------------------------

# Readable names for the columns that show up in the history.
FIELD_LABELS = {
    "status": "status", "owner": "owner", "applicable": "applicability",
    "justification": "justification", "evidence": "evidence", "notes": "notes",
    "asset": "asset", "asset_type": "asset type", "threat": "threat",
    "vulnerability": "vulnerability", "existing_controls": "existing controls",
    "likelihood": "likelihood", "impact": "impact", "treatment": "treatment",
    "treatment_plan": "treatment plan", "res_likelihood": "residual likelihood",
    "res_impact": "residual impact", "target_date": "target date",
    "controls": "linked controls", "code": "code", "title": "title",
    "doc_type": "type", "version": "version", "approved_on": "approval date",
    "next_review": "next review", "clause_ref": "clause", "source": "source",
    "raised_on": "raised on", "clause_or_control": "clause or control",
    "description": "description", "severity": "severity", "root_cause": "root cause",
    "corrective_action": "corrective action", "due_date": "due date",
    "closed_on": "closed on", "role": "role", "assignee_id": "assignee",
}


def now_utc():
    """The real clock, not the pinned TODAY: history must say when it happened."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _as_text(field, value):
    if value is None or value == "":
        return ""
    if field == "applicable":
        return "Applicable" if str(value) == "1" else "Excluded"
    if field == "assignee_id":
        user = query("SELECT name FROM users WHERE id = ?", (value,), one=True)
        return user["name"] if user else f"user #{value}"
    return str(value)


def log(user, entity_type, entity_id, entity_ref, action, changes=()):
    """Record one action. `changes` is a list of (field, old, new); an update
    writes one row per changed field, anything else writes a single row."""
    at = now_utc()
    rows = [(field, old, new) for field, old, new in changes] or [(None, None, None)]
    conn = connect()
    try:
        conn.executemany(
            """INSERT INTO activity (user_id, user_name, entity_type, entity_id,
               entity_ref, action, field, old_value, new_value, at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            [(user["id"], user["name"], entity_type, entity_id, entity_ref, action,
              field, old, new, at) for field, old, new in rows],
        )
        conn.commit()
    finally:
        conn.close()


def log_update(user, entity_type, entity_id, entity_ref, before, after):
    """Compare a row before and after a save and log only what changed."""
    changes = []
    for field, new in after.items():
        old_text = _as_text(field, before[field] if field in before.keys() else None)
        new_text = _as_text(field, new)
        if old_text != new_text:
            changes.append((field, old_text, new_text))
    if changes:
        log(user, entity_type, entity_id, entity_ref, "updated", changes)


def recent_activity(limit=10):
    return query("SELECT * FROM activity ORDER BY id DESC LIMIT ?", (limit,))


def history(entity_type, entity_id, limit=100):
    return query(
        """SELECT * FROM activity WHERE entity_type = ? AND entity_id = ?
           ORDER BY id DESC LIMIT ?""",
        (entity_type, entity_id, limit),
    )


# ---------------------------------------------------------------------------
# Comments and evidence files
# ---------------------------------------------------------------------------

def comments_for(entity_type, entity_id):
    return query(
        "SELECT * FROM comments WHERE entity_type = ? AND entity_id = ? ORDER BY id",
        (entity_type, entity_id),
    )


def evidence_for(control_id):
    return query(
        "SELECT * FROM evidence_files WHERE control_id = ? ORDER BY id DESC", (control_id,)
    )


# ---------------------------------------------------------------------------
# Readiness over time
# ---------------------------------------------------------------------------

def snapshot_readiness(stats):
    """Record today's readiness (real date), replacing an earlier reading
    from the same day."""
    execute(
        """INSERT INTO readiness_snapshots (day, overall, controls, clauses, documents)
           VALUES (?,?,?,?,?)
           ON CONFLICT(day) DO UPDATE SET overall = excluded.overall,
               controls = excluded.controls, clauses = excluded.clauses,
               documents = excluded.documents""",
        (datetime.now(timezone.utc).strftime("%Y-%m-%d"), stats["overall"],
         stats["controls"]["percent"], stats["clauses"]["percent"],
         stats["documents"]["percent"]),
    )


def readiness_history(limit=26):
    """The most recent readings, oldest first."""
    rows = query("SELECT * FROM readiness_snapshots ORDER BY day DESC LIMIT ?", (limit,))
    return list(reversed(rows))


# ---------------------------------------------------------------------------
# Assigned work ("My tasks")
# ---------------------------------------------------------------------------

def people():
    """Everyone who can be assigned work, for the 'Assigned to' dropdowns."""
    return query("SELECT id, name, role FROM users ORDER BY name")


def open_tasks(user_id):
    """Everything assigned to one person that is still to do, soonest due
    first. A control counts as done for its assignee once it is Implemented;
    verifying it is the auditor's job, not theirs."""
    return query(
        """SELECT * FROM (
           SELECT 'control' AS kind, id, ref, title AS what, status, due_date AS due
             FROM controls
            WHERE assignee_id = ? AND applicable = 1
              AND status IN ('Not Started', 'In Progress')
           UNION ALL
           SELECT 'risk', id, ref, asset || ': ' || COALESCE(threat, ''), status, target_date
             FROM risks
            WHERE assignee_id = ? AND status != 'Closed'
           UNION ALL
           SELECT 'finding', id, ref, description, status, due_date
             FROM findings
            WHERE assignee_id = ? AND status != 'Closed'
           )
           ORDER BY due IS NULL, due, ref""",
        (user_id, user_id, user_id),
    )


def overdue(tasks):
    today = TODAY.strftime("%Y-%m-%d")
    return [t for t in tasks if t["due"] and t["due"] < today]


# ---------------------------------------------------------------------------
# Statement of Applicability justifications
# ---------------------------------------------------------------------------

# Opening words of every justification this module (or the seed) writes. A
# justification starting any other way was typed by a person and is kept.
_AUTO_JUSTIFICATION_PREFIXES = (
    "Selected to treat identified risk",
    "Adopted as baseline practice",
    "Applicable to the organisation's operations",
    "Relevant to the scope of the ISMS",
)


def refresh_justifications(conn=None):
    """Re-derive SoA justifications from the risks and documents linked to
    each applicable control.

    A justification of real audit value cites *why* the control is in scope.
    Where a control treats an identified risk, name that risk; where it is
    evidenced by a document, name that document. Only controls with neither
    fall back to a baseline-practice statement. Hand-written justifications
    are left alone.
    """
    own_conn = conn is None
    if own_conn:
        conn = connect()
    try:
        for row in conn.execute(
            "SELECT id, justification FROM controls WHERE applicable = 1"
        ).fetchall():
            current = row["justification"] or ""
            if current and not current.startswith(_AUTO_JUSTIFICATION_PREFIXES):
                continue

            risk_refs = [
                r["ref"]
                for r in conn.execute(
                    """SELECT r.ref FROM risks r
                       JOIN risk_controls rc ON rc.risk_id = r.id
                       WHERE rc.control_id = ? ORDER BY r.ref""",
                    (row["id"],),
                )
            ]
            doc_codes = [
                d["code"]
                for d in conn.execute(
                    """SELECT d.code FROM documents d
                       JOIN doc_controls dc ON dc.document_id = d.id
                       WHERE dc.control_id = ? ORDER BY d.code""",
                    (row["id"],),
                )
            ]

            if risk_refs:
                text = (
                    f"Selected to treat identified risk{'s' if len(risk_refs) > 1 else ''} "
                    f"{', '.join(risk_refs)} recorded in the risk register."
                )
                if doc_codes:
                    text += f" Evidenced by {', '.join(doc_codes)}."
            elif doc_codes:
                text = (
                    "Adopted as baseline practice for the organisation and evidenced by "
                    f"{', '.join(doc_codes)}."
                )
            else:
                text = (
                    "Applicable to the organisation's operations and retained as baseline "
                    "good practice. No specific risk is currently mapped; to be reviewed at "
                    "the next risk assessment cycle."
                )

            if text != current:
                conn.execute(
                    "UPDATE controls SET justification = ? WHERE id = ?", (text, row["id"])
                )
        if own_conn:
            conn.commit()
    finally:
        if own_conn:
            conn.close()


# ---------------------------------------------------------------------------
# Risk scoring - 5x5 likelihood / impact matrix
# ---------------------------------------------------------------------------

def risk_score(likelihood, impact):
    if not likelihood or not impact:
        return None
    return int(likelihood) * int(impact)


def risk_level(score):
    """Map a 1-25 score onto the four bands used in the risk register."""
    if score is None:
        return "Unscored"
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 14:
        return "High"
    return "Critical"


def risk_level_class(level):
    return {
        "Low": "lvl-low",
        "Medium": "lvl-med",
        "High": "lvl-high",
        "Critical": "lvl-crit",
    }.get(level, "lvl-none")


# ---------------------------------------------------------------------------
# Readiness statistics
# ---------------------------------------------------------------------------

def _weighted_percent(rows):
    """Average the status weights of a set of rows, as a percentage."""
    rows = list(rows)
    if not rows:
        return 0.0
    total = sum(STATUS_WEIGHT.get(r["status"], 0.0) for r in rows)
    return round(100.0 * total / len(rows), 1)


def control_stats():
    """Status breakdown and completion for applicable controls only.

    Excluded controls are deliberately left out: a control ruled out of scope
    in the Statement of Applicability cannot be 'incomplete'.
    """
    applicable = query("SELECT status FROM controls WHERE applicable = 1")
    counts = {s: 0 for s in CONTROL_STATUSES}
    for row in applicable:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    excluded = query("SELECT COUNT(*) c FROM controls WHERE applicable = 0", one=True)["c"]
    return {
        "counts": counts,
        "applicable": len(applicable),
        "excluded": excluded,
        "total": len(applicable) + excluded,
        "percent": _weighted_percent(applicable),
    }


def theme_stats():
    """Per-theme completion, used for the dashboard bar chart."""
    out = []
    for theme in THEMES:
        rows = query(
            "SELECT status FROM controls WHERE applicable = 1 AND theme = ?", (theme,)
        )
        out.append(
            {
                "theme": theme,
                "count": len(rows),
                "percent": _weighted_percent(rows),
            }
        )
    return out


def clause_stats():
    rows = query("SELECT status FROM clauses")
    counts = {s: 0 for s in CLAUSE_STATUSES}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {"counts": counts, "total": len(rows), "percent": _weighted_percent(rows)}


def document_stats():
    rows = query("SELECT status FROM documents")
    counts = {s: 0 for s in DOC_STATUSES}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    live = [r for r in rows if r["status"] != "Obsolete"]
    approved = counts.get("Approved", 0)
    percent = round(100.0 * approved / len(live), 1) if live else 0.0
    return {"counts": counts, "total": len(rows), "approved": approved, "percent": percent}


def risk_stats():
    rows = query("SELECT likelihood, impact, res_likelihood, res_impact, status FROM risks")
    bands = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    open_count = 0
    for row in rows:
        # Score an open risk on its residual position if treatment has been
        # planned, otherwise on its inherent position.
        lk = row["res_likelihood"] or row["likelihood"]
        im = row["res_impact"] or row["impact"]
        bands[risk_level(risk_score(lk, im))] += 1
        if row["status"] != "Closed":
            open_count += 1
    return {"bands": bands, "total": len(rows), "open": open_count}


def finding_stats():
    rows = query("SELECT severity, status FROM findings")
    open_rows = [r for r in rows if r["status"] != "Closed"]
    return {
        "total": len(rows),
        "open": len(open_rows),
        "major_open": len([r for r in open_rows if r["severity"] == "Major"]),
    }


def readiness():
    """Overall certification readiness across the three work streams."""
    c, cl, d = control_stats(), clause_stats(), document_stats()
    overall = (
        c["percent"] * READINESS_WEIGHTS["controls"]
        + cl["percent"] * READINESS_WEIGHTS["clauses"]
        + d["percent"] * READINESS_WEIGHTS["documents"]
    )
    return {
        "controls": c,
        "clauses": cl,
        "documents": d,
        "risks": risk_stats(),
        "findings": finding_stats(),
        "overall": round(overall, 1),
    }
