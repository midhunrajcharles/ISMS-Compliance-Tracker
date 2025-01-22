"""Tests for the ISMS Compliance Tracker.

Run with:  pytest

Every test gets a freshly seeded database in a temporary folder, so the real
isms.db and uploads/ folder are never touched.
"""

import os
import tempfile

# Point the app at a throwaway database *before* it is imported, because
# db.py reads the path once at import time.
_TMP = tempfile.mkdtemp()
os.environ["ISMS_DB_PATH"] = os.path.join(_TMP, "test.db")
os.environ["ISMS_UPLOAD_DIR"] = os.path.join(_TMP, "uploads")

import pytest

import app as app_module
import db
import seed

RISK_FORM = {
    "asset": "Test laptop",
    "asset_type": "Hardware",
    "threat": "Theft",
    "vulnerability": "No disk encryption",
    "existing_controls": "",
    "likelihood": "3",
    "impact": "4",
    "treatment": "Modify",
    "treatment_plan": "Encrypt disks",
    "res_likelihood": "",
    "res_impact": "",
    "owner": "IT",
    "target_date": "2025-03-01",
    "status": "Open",
}

DOC_FORM = {
    "code": "ISMS-TEST-01",
    "title": "Test policy",
    "doc_type": "Policy",
    "version": "1.0",
    "owner": "ISMS Manager",
    "status": "Draft",
}


@pytest.fixture
def anon():
    """A browser that has not signed in, on a freshly seeded database."""
    seed.build()
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def post(client, url, data=None, **kw):
    """POST a form the way the browser does: with the session's CSRF token."""
    client.get("/")                         # any rendered form creates the token
    with client.session_transaction() as sess:
        token = sess.setdefault("csrf", "test-token")
    return client.post(url, data={**(data or {}), "csrf_token": token}, **kw)


def login(client, email, password):
    return post(client, "/login", {"email": email, "password": password})


@pytest.fixture
def client(anon):
    """Signed in as the demo admin."""
    login(anon, "admin@example.com", "admin123")
    return anon


def as_role(client, role):
    post(client, "/logout")
    login(client, f"{role}@example.com", "demo1234")
    return client


@pytest.mark.parametrize(
    "url",
    ["/", "/controls", "/controls/A.8.13", "/clauses", "/risks", "/risks/new",
     "/documents", "/documents/new", "/soa", "/soa/export.csv", "/audit",
     "/audit/new", "/gap", "/users", "/profile", "/activity", "/my-tasks"],
)
def test_every_page_loads(client, url):
    assert client.get(url).status_code == 200


def test_today_has_one_source():
    assert app_module.TODAY is db.TODAY
    assert seed.TODAY is db.TODAY


# ---- 0.1 duplicate document code -------------------------------------------

def test_duplicate_document_code_shows_message_not_crash(client):
    existing = db.query("SELECT code FROM documents LIMIT 1", one=True)["code"]
    before = db.query("SELECT COUNT(*) c FROM documents", one=True)["c"]

    resp = post(client, "/documents/new", data={**DOC_FORM, "code": existing})

    assert resp.status_code == 400
    assert b"already exists" in resp.data
    assert b"Test policy" in resp.data          # typed values are kept
    assert db.query("SELECT COUNT(*) c FROM documents", one=True)["c"] == before


def test_new_document_with_unique_code_saves(client):
    resp = post(client, "/documents/new", data=DOC_FORM)
    assert resp.status_code == 302
    assert db.query("SELECT 1 FROM documents WHERE code = ?", ("ISMS-TEST-01",), one=True)


# ---- 0.2 risk score validation ---------------------------------------------

@pytest.mark.parametrize(
    "bad",
    [{"likelihood": ""}, {"likelihood": "0"}, {"impact": "6"}, {"impact": "abc"},
     {"res_likelihood": "9"}],
)
def test_bad_risk_scores_are_rejected(client, bad):
    before = db.query("SELECT COUNT(*) c FROM risks", one=True)["c"]

    resp = post(client, "/risks/new", data={**RISK_FORM, **bad})

    assert resp.status_code == 400
    assert b"1 to 5" in resp.data
    assert db.query("SELECT COUNT(*) c FROM risks", one=True)["c"] == before


def test_valid_risk_saves(client):
    resp = post(client, "/risks/new", data=RISK_FORM)
    assert resp.status_code == 302
    assert db.query("SELECT 1 FROM risks WHERE asset = 'Test laptop'", one=True)


# ---- 0.3 live SoA justifications ---------------------------------------------

def _justification(ref):
    return db.query("SELECT justification FROM controls WHERE ref = ?", (ref,), one=True)[0]


def test_linking_a_risk_updates_justification(client):
    # Pick an applicable control that no risk treats yet.
    ref = db.query(
        """SELECT c.ref FROM controls c
           LEFT JOIN risk_controls rc ON rc.control_id = c.id
           WHERE c.applicable = 1 AND rc.control_id IS NULL LIMIT 1""",
        one=True,
    )["ref"]
    assert "Selected to treat" not in _justification(ref)

    post(client, "/risks/new", data={**RISK_FORM, "controls": [ref]})

    new_ref = db.query("SELECT ref FROM risks ORDER BY id DESC LIMIT 1", one=True)["ref"]
    assert f"Selected to treat identified risk {new_ref}" in _justification(ref)


def test_hand_written_justification_is_kept(client):
    c = db.query("SELECT * FROM controls WHERE ref = 'A.8.13'", one=True)
    form = {
        "status": c["status"], "owner": c["owner"] or "", "applicable": "1",
        "justification": "Required by our customer contract.",
        "evidence": "", "notes": "",
    }
    post(client, "/controls/A.8.13", data=form)
    post(client, "/risks/new", data={**RISK_FORM, "controls": ["A.8.13"]})

    assert _justification("A.8.13") == "Required by our customer contract."


# ---- Phase 1: sign-in, roles, CSRF ---------------------------------------------

def test_pages_need_login(anon):
    resp = anon.get("/risks")
    assert resp.status_code == 302
    assert "/login?next=/risks" in resp.headers["Location"]


def test_wrong_password_is_refused(anon):
    resp = login(anon, "admin@example.com", "wrong-password")
    assert resp.status_code == 401
    assert b"Email or password is wrong" in resp.data
    assert anon.get("/").status_code == 302


def test_login_follows_next_but_not_to_other_sites(anon):
    anon.get("/login")
    with anon.session_transaction() as sess:
        token = sess["csrf"]
    form = {"email": "admin@example.com", "password": "admin123", "csrf_token": token}
    resp = anon.post("/login?next=//evil.example.com", data=form)
    assert resp.headers["Location"] == "/"


def test_logout_ends_the_session(client):
    post(client, "/logout")
    assert client.get("/").status_code == 302


def test_form_without_csrf_token_is_rejected(client):
    resp = client.post("/risks/new", data=RISK_FORM)
    assert resp.status_code == 400
    assert b"expired" in resp.data


def test_viewer_can_read_but_not_change(client):
    as_role(client, "viewer")
    assert client.get("/risks").status_code == 200
    assert post(client, "/risks/new", RISK_FORM).status_code == 403
    assert post(client, "/audit/new", {}).status_code == 403
    assert b"Read only for your role" in client.get("/controls/A.8.13").data


def test_auditor_can_raise_findings_only(client):
    as_role(client, "auditor")
    assert post(client, "/risks/new", RISK_FORM).status_code == 403
    finding = {
        "source": "Internal Audit", "raised_on": "2025-01-20", "clause_or_control": "A.8.13",
        "description": "Restore test missing", "severity": "Minor", "root_cause": "",
        "corrective_action": "", "owner": "IT", "due_date": "2025-02-20", "status": "Open",
    }
    assert post(client, "/audit/new", finding).status_code == 302


def test_only_admin_manages_users(client):
    as_role(client, "editor")
    assert client.get("/users").status_code == 403
    assert post(client, "/users", {"name": "X", "email": "x@x.com", "role": "admin",
                                   "password": "longenough"}).status_code == 403


def test_admin_creates_account_that_can_log_in(client):
    resp = post(client, "/users", {"name": "Priya", "email": "Priya@Example.com",
                                   "role": "editor", "password": "priya-pass"})
    assert resp.status_code == 302
    post(client, "/logout")
    login(client, "priya@example.com", "priya-pass")
    assert client.get("/").status_code == 200


def test_duplicate_account_email_shows_message(client):
    resp = post(client, "/users", {"name": "Dup", "email": "viewer@example.com",
                                   "role": "viewer", "password": "longenough"})
    assert resp.status_code == 400
    assert b"already exists" in resp.data


def test_admin_cannot_change_own_role(client):
    me = db.query("SELECT id FROM users WHERE email = 'admin@example.com'", one=True)["id"]
    post(client, f"/users/{me}", {"action": "role", "role": "viewer"})
    assert db.query("SELECT role FROM users WHERE id = ?", (me,), one=True)["role"] == "admin"


def test_change_own_password(client):
    bad = post(client, "/profile", {"current": "nope", "new": "newpass99", "confirm": "newpass99"})
    assert bad.status_code == 400
    ok = post(client, "/profile", {"current": "admin123", "new": "newpass99", "confirm": "newpass99"})
    assert ok.status_code == 302
    post(client, "/logout")
    assert login(client, "admin@example.com", "newpass99").status_code == 302


def test_passwords_are_hashed_not_stored():
    seed.build()
    for row in db.query("SELECT password_hash FROM users"):
        assert "admin123" not in row["password_hash"]
        assert "demo1234" not in row["password_hash"]


# ---- Phase 2: activity history ---------------------------------------------------

def _control_form(ref, **changes):
    c = db.query("SELECT * FROM controls WHERE ref = ?", (ref,), one=True)
    form = {
        "status": c["status"], "owner": c["owner"] or "",
        "applicable": "1" if c["applicable"] else "0",
        "justification": c["justification"] or "", "evidence": c["evidence"] or "",
        "notes": c["notes"] or "",
    }
    return {**form, **changes}


def test_changing_a_control_is_logged_with_who_and_what(client):
    old = db.query("SELECT status FROM controls WHERE ref = 'A.8.13'", one=True)["status"]
    new = "Verified" if old != "Verified" else "In Progress"

    post(client, "/controls/A.8.13", _control_form("A.8.13", status=new))

    rows = db.query("SELECT * FROM activity WHERE entity_ref = 'A.8.13'")
    assert len(rows) == 1                       # only the field that changed
    a = rows[0]
    assert (a["user_name"], a["field"], a["old_value"], a["new_value"]) == \
        ("ISMS Admin", "status", old, new)


def test_saving_without_changes_logs_nothing(client):
    post(client, "/controls/A.8.13", _control_form("A.8.13"))
    assert db.query("SELECT COUNT(*) c FROM activity", one=True)["c"] == 0


def test_history_shows_on_detail_page_and_dashboard(client):
    post(client, "/controls/A.8.13", _control_form("A.8.13", owner="Ravi"))
    detail = client.get("/controls/A.8.13").data
    assert b"History" in detail and b"Ravi" in detail and b"just now" in detail
    assert b"of control" in client.get("/").data
    assert b"A.8.13" in client.get("/activity").data


def test_new_risk_and_linked_controls_are_logged(client):
    post(client, "/risks/new", {**RISK_FORM, "controls": ["A.8.13"]})
    risk = db.query("SELECT id, ref FROM risks ORDER BY id DESC LIMIT 1", one=True)
    created = db.history("risk", risk["id"])
    assert [a["action"] for a in created] == ["created"]

    post(client, f"/risks/{risk['id']}", {**RISK_FORM, "impact": "5",
                                          "controls": ["A.8.13", "A.5.15"]})
    changed = {a["field"]: (a["old_value"], a["new_value"]) for a in db.history("risk", risk["id"])
               if a["action"] == "updated"}
    assert changed["impact"] == ("4", "5")
    assert changed["controls"] == ("A.8.13", "A.5.15, A.8.13")


def test_auditor_finding_is_logged_under_their_name(client):
    as_role(client, "auditor")
    finding = {
        "source": "Internal Audit", "raised_on": "2025-01-20", "clause_or_control": "A.8.13",
        "description": "Restore test missing", "severity": "Minor", "root_cause": "",
        "corrective_action": "", "owner": "IT", "due_date": "2025-02-20", "status": "Open",
    }
    post(client, "/audit/new", finding)
    a = db.query("SELECT * FROM activity WHERE entity_type = 'finding'", one=True)
    assert a["user_name"] == "Internal Auditor" and a["action"] == "created"


def test_password_changes_are_logged_without_the_password(client):
    post(client, "/profile", {"current": "admin123", "new": "newpass99", "confirm": "newpass99"})
    a = db.query("SELECT * FROM activity WHERE entity_type = 'user'", one=True)
    assert a["action"] == "changed own password"
    assert not a["old_value"] and not a["new_value"]


def test_ago_filter():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    fmt = lambda d: d.strftime("%Y-%m-%d %H:%M:%S")
    assert app_module.ago(fmt(now)) == "just now"
    assert app_module.ago(fmt(now - timedelta(minutes=5))) == "5 min ago"
    assert app_module.ago(fmt(now - timedelta(hours=2))) == "2h ago"
    assert app_module.ago(fmt(now - timedelta(days=3))) == "3 days ago"


# ---- Phase 3: assignments and My tasks ---------------------------------------------

def _uid(email):
    return db.query("SELECT id FROM users WHERE email = ?", (email,), one=True)["id"]


def test_demo_editor_has_tasks_and_some_are_overdue():
    seed.build()
    tasks = db.open_tasks(_uid("editor@example.com"))
    assert tasks
    assert db.overdue(tasks)
    dues = [t["due"] for t in tasks if t["due"]]
    assert dues == sorted(dues)                 # soonest first


def test_assigning_a_control_puts_it_in_my_tasks(client):
    viewer = _uid("viewer@example.com")
    post(client, "/controls/A.5.1", _control_form(
        "A.5.1", status="In Progress", assignee_id=str(viewer), due_date="2025-01-01"))

    tasks = db.open_tasks(viewer)
    assert [t["ref"] for t in tasks] == ["A.5.1"]
    assert db.overdue(tasks)                    # 1 Jan is before the pinned today

    a = db.query("SELECT * FROM activity WHERE field = 'assignee_id'", one=True)
    assert a["new_value"] == "External Auditor"     # logged as a name, not an id


def test_implemented_control_leaves_the_task_list(client):
    me = _uid("admin@example.com")
    post(client, "/controls/A.5.1", _control_form("A.5.1", status="In Progress", assignee_id=str(me)))
    assert "A.5.1" in [t["ref"] for t in db.open_tasks(me)]
    post(client, "/controls/A.5.1", _control_form("A.5.1", status="Implemented", assignee_id=str(me)))
    assert "A.5.1" not in [t["ref"] for t in db.open_tasks(me)]


def test_unknown_assignee_and_bad_date_are_ignored(client):
    post(client, "/controls/A.5.1", _control_form("A.5.1", assignee_id="9999", due_date="soon"))
    c = db.query("SELECT assignee_id, due_date FROM controls WHERE ref = 'A.5.1'", one=True)
    assert c["assignee_id"] is None and c["due_date"] is None


def test_risk_and_finding_can_be_assigned(client):
    ravi = _uid("editor@example.com")
    before = len(db.open_tasks(ravi))
    post(client, "/risks/new", {**RISK_FORM, "assignee_id": str(ravi)})
    finding = {
        "source": "Internal Audit", "raised_on": "2025-01-20", "clause_or_control": "A.8.13",
        "description": "Restore test missing", "severity": "Minor", "root_cause": "",
        "corrective_action": "", "owner": "IT", "due_date": "2025-02-20", "status": "Open",
        "assignee_id": str(ravi),
    }
    post(client, "/audit/new", finding)
    assert len(db.open_tasks(ravi)) == before + 2


def test_sidebar_badge_and_page(client):
    as_role(client, "editor")
    html = client.get("/my-tasks").data
    assert b"count overdue" in html              # red badge in the sidebar
    assert b"days late" in html or b"day late" in html
    other = client.get(f"/my-tasks?user={_uid('admin@example.com')}").data
    assert "ISMS Admin’s tasks".encode() in other


def test_old_database_is_upgraded_without_losing_data(tmp_path):
    """A database from before Phase 1 gains users, activity and assignee
    columns on start-up, and keeps its rows."""
    import sqlite3
    old = tmp_path / "old.db"
    conn = sqlite3.connect(old)
    conn.executescript("""
        CREATE TABLE controls (id INTEGER PRIMARY KEY, ref TEXT, status TEXT, owner TEXT);
        CREATE TABLE risks (id INTEGER PRIMARY KEY, ref TEXT, status TEXT);
        CREATE TABLE findings (id INTEGER PRIMARY KEY, ref TEXT, status TEXT);
        INSERT INTO controls (ref, status, owner) VALUES ('A.5.1', 'Verified', 'Me');
    """)
    conn.commit()
    conn.close()

    saved = db.DB_PATH
    db.DB_PATH = str(old)
    try:
        db.ensure_tables()
        db.ensure_tables()                      # running twice is harmless
        cols = [r[1] for r in db.query("PRAGMA table_info(controls)")]
        assert "assignee_id" in cols and "due_date" in cols
        assert db.query("SELECT owner FROM controls", one=True)["owner"] == "Me"
        assert db.query("SELECT COUNT(*) c FROM users", one=True)["c"] == 4
    finally:
        db.DB_PATH = saved


# ---- Phase 4: comments and evidence files -------------------------------------------

import io

PDF = b"%PDF-1.4\n1 0 obj << >> endobj\n%%EOF\n"


def _control_id(ref="A.8.13"):
    return db.query("SELECT id FROM controls WHERE ref = ?", (ref,), one=True)["id"]


def _upload(client, name, data, ref="A.8.13"):
    return post(client, f"/controls/{ref}/evidence",
                {"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")


def test_comment_is_posted_shown_and_logged(client):
    cid = _control_id()
    resp = post(client, "/comments", {"entity_type": "control", "entity_id": str(cid),
                                      "body": "Waiting on IT for the backup test"})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("#comments")
    page = client.get("/controls/A.8.13").data
    assert b"Waiting on IT for the backup test" in page
    a = db.query("SELECT * FROM activity WHERE action = 'commented'", one=True)
    assert a["entity_ref"] == "A.8.13"


def test_comments_on_risks_and_findings(client):
    post(client, "/comments", {"entity_type": "risk", "entity_id": "1", "body": "Risk note"})
    post(client, "/comments", {"entity_type": "finding", "entity_id": "1", "body": "Finding note"})
    assert b"Risk note" in client.get("/risks/1").data
    assert b"Finding note" in client.get("/audit/1").data


def test_empty_or_bad_comments_are_refused(client):
    cid = str(_control_id())
    post(client, "/comments", {"entity_type": "control", "entity_id": cid, "body": "   "})
    post(client, "/comments", {"entity_type": "control", "entity_id": cid, "body": "x" * 2001})
    assert db.query("SELECT COUNT(*) c FROM comments", one=True)["c"] == 0
    assert post(client, "/comments", {"entity_type": "users", "entity_id": "1",
                                      "body": "hi"}).status_code == 404
    assert post(client, "/comments", {"entity_type": "control", "entity_id": "99999",
                                      "body": "hi"}).status_code == 404


def test_comment_html_is_escaped(client):
    post(client, "/comments", {"entity_type": "control", "entity_id": str(_control_id()),
                               "body": "<script>alert(1)</script>"})
    page = client.get("/controls/A.8.13").data
    assert b"<script>alert(1)</script>" not in page
    assert b"&lt;script&gt;" in page


def test_who_may_comment(client):
    cid = str(_control_id())
    as_role(client, "auditor")
    assert post(client, "/comments", {"entity_type": "control", "entity_id": cid,
                                      "body": "Auditor note"}).status_code == 302
    as_role(client, "viewer")
    assert post(client, "/comments", {"entity_type": "control", "entity_id": cid,
                                      "body": "Viewer note"}).status_code == 403


def test_upload_view_and_download_evidence(client):
    resp = _upload(client, "backup-report.pdf", PDF)
    assert resp.status_code == 302
    ev = db.query("SELECT * FROM evidence_files", one=True)
    assert ev["original_name"] == "backup-report.pdf" and ev["size"] == len(PDF)
    assert ev["uploaded_by_name"] == "ISMS Admin"
    assert "backup-report" not in ev["stored_name"]     # random name on disk
    assert os.path.exists(os.path.join(db.UPLOAD_DIR, ev["stored_name"]))

    view = client.get(f"/evidence/{ev['id']}")
    assert view.status_code == 200 and view.data == PDF
    assert view.headers["Content-Type"] == "application/pdf"
    assert view.headers["X-Content-Type-Options"] == "nosniff"
    down = client.get(f"/evidence/{ev['id']}?download=1")
    assert "attachment" in down.headers["Content-Disposition"]

    page = client.get("/controls/A.8.13").data
    assert b"backup-report.pdf" in page and b"ISMS Admin" in page
    assert db.query("SELECT 1 FROM activity WHERE action = 'uploaded evidence'", one=True)


@pytest.mark.parametrize("name,data", [
    ("tool.exe", b"MZ\x90\x00"),                   # not an allowed type
    ("page.html", b"<html></html>"),
    ("fake.pdf", b"MZ\x90\x00 this is a program"),  # wrong content for .pdf
    ("fake.png", PDF),
    ("binary.txt", b"abc\x00def"),
    ("empty.pdf", b""),
])
def test_bad_uploads_are_refused(client, name, data):
    _upload(client, name, data)
    assert db.query("SELECT COUNT(*) c FROM evidence_files", one=True)["c"] == 0


def test_too_big_upload_is_refused(client):
    resp = _upload(client, "big.pdf", b"%PDF-" + b"0" * (11 * 1024 * 1024))
    assert resp.status_code == 413
    assert b"too big" in resp.data
    assert db.query("SELECT COUNT(*) c FROM evidence_files", one=True)["c"] == 0


def test_file_name_cannot_escape_the_upload_folder(client):
    _upload(client, "../../../evil.pdf", PDF)
    ev = db.query("SELECT * FROM evidence_files", one=True)
    assert ev["original_name"] == "evil.pdf"
    assert os.path.dirname(os.path.join(db.UPLOAD_DIR, ev["stored_name"])) == db.UPLOAD_DIR


def test_evidence_needs_login(client):
    _upload(client, "r.pdf", PDF)
    fid = db.query("SELECT id FROM evidence_files", one=True)["id"]
    post(client, "/logout")
    assert client.get(f"/evidence/{fid}").status_code == 302


def test_who_may_upload_and_delete(client):
    as_role(client, "editor")
    _upload(client, "ravi.pdf", PDF)
    fid = db.query("SELECT id FROM evidence_files", one=True)["id"]

    as_role(client, "viewer")
    assert _upload(client, "v.pdf", PDF).status_code == 403
    assert post(client, f"/evidence/{fid}/delete").status_code == 403

    as_role(client, "editor")                            # the uploader may delete
    stored = db.query("SELECT stored_name FROM evidence_files", one=True)["stored_name"]
    assert post(client, f"/evidence/{fid}/delete").status_code == 302
    assert db.query("SELECT COUNT(*) c FROM evidence_files", one=True)["c"] == 0
    assert not os.path.exists(os.path.join(db.UPLOAD_DIR, stored))


def test_editor_cannot_delete_someone_elses_file(client):
    _upload(client, "admin.pdf", PDF)                    # uploaded by the admin
    fid = db.query("SELECT id FROM evidence_files", one=True)["id"]
    as_role(client, "editor")
    assert post(client, f"/evidence/{fid}/delete").status_code == 403


# ---- Phase 5: delete, archive, bulk update, duplicate ---------------------------------

def test_delete_asks_first_then_removes_risk_links_and_comments(client):
    rid = db.query("SELECT r.id FROM risks r JOIN risk_controls rc ON rc.risk_id = r.id LIMIT 1",
                   one=True)["id"]
    ref = db.query("SELECT ref FROM risks WHERE id = ?", (rid,), one=True)["ref"]
    post(client, "/comments", {"entity_type": "risk", "entity_id": str(rid), "body": "note"})

    confirm = client.get(f"/delete/risk/{rid}")
    assert confirm.status_code == 200 and b"cannot be undone" in confirm.data
    assert db.query("SELECT 1 FROM risks WHERE id = ?", (rid,), one=True)   # not yet

    assert post(client, f"/delete/risk/{rid}").status_code == 302
    assert not db.query("SELECT 1 FROM risks WHERE id = ?", (rid,), one=True)
    assert not db.query("SELECT 1 FROM risk_controls WHERE risk_id = ?", (rid,), one=True)
    assert not db.query("SELECT 1 FROM comments WHERE entity_type = 'risk' AND entity_id = ?",
                        (rid,), one=True)
    # SoA justifications no longer cite the deleted risk
    assert not db.query("SELECT 1 FROM controls WHERE justification LIKE ?", (f"%{ref},%",), one=True)
    assert not db.query("SELECT 1 FROM controls WHERE justification LIKE ?", (f"%{ref} %",), one=True)
    # the deletion itself is on record, and the feed still renders
    assert db.query("SELECT 1 FROM activity WHERE action = 'deleted' AND entity_ref = ?",
                    (ref,), one=True)
    assert f"deleted risk {ref}".encode() in client.get("/activity").data


def test_delete_document_and_finding(client):
    did = db.query("SELECT id FROM documents LIMIT 1", one=True)["id"]
    fid = db.query("SELECT id FROM findings LIMIT 1", one=True)["id"]
    post(client, f"/delete/document/{did}")
    post(client, f"/delete/finding/{fid}")
    assert not db.query("SELECT 1 FROM documents WHERE id = ?", (did,), one=True)
    assert not db.query("SELECT 1 FROM doc_controls WHERE document_id = ?", (did,), one=True)
    assert not db.query("SELECT 1 FROM findings WHERE id = ?", (fid,), one=True)


def test_only_admin_can_delete(client):
    as_role(client, "editor")
    assert client.get("/delete/risk/1").status_code == 403
    assert post(client, "/delete/risk/1").status_code == 403
    assert db.query("SELECT 1 FROM risks WHERE id = 1", one=True)
    assert b"Delete" not in client.get("/risks/1").data.split(b"page-head", 2)[1]


def test_delete_unknown_kind_or_item_is_404(client):
    assert client.get("/delete/control/1").status_code == 404
    assert client.get("/delete/risk/99999").status_code == 404


def test_archive_document_keeps_it_but_hides_it(client):
    doc = db.query("SELECT * FROM documents WHERE status != 'Obsolete' LIMIT 1", one=True)
    as_role(client, "editor")                           # editors may archive
    assert post(client, f"/documents/{doc['id']}/archive").status_code == 302
    assert db.query("SELECT status FROM documents WHERE id = ?", (doc["id"],),
                    one=True)["status"] == "Obsolete"
    client.get("/")                                     # shows (and clears) the flash message
    assert doc["code"].encode() not in client.get("/documents").data
    assert doc["code"].encode() in client.get("/documents?archived=1").data
    assert db.query("SELECT 1 FROM activity WHERE entity_type = 'document' AND new_value = 'Obsolete'",
                    one=True)


def test_bulk_update_sets_status_and_logs_each(client):
    refs = [r["ref"] for r in db.query(
        "SELECT ref FROM controls WHERE applicable = 1 AND status = 'Not Started' LIMIT 3")]
    excluded = db.query("SELECT ref FROM controls WHERE applicable = 0 LIMIT 1", one=True)["ref"]

    resp = post(client, "/controls/bulk", {"refs": refs + [excluded], "status": "In Progress",
                                           "back": "/controls?status=Not+Started"})
    assert resp.headers["Location"] == "/controls?status=Not+Started"
    for ref in refs:
        assert db.query("SELECT status FROM controls WHERE ref = ?", (ref,),
                        one=True)["status"] == "In Progress"
    assert db.query("SELECT status FROM controls WHERE ref = ?", (excluded,),
                    one=True)["status"] == "Not Started"
    assert db.query("SELECT COUNT(*) c FROM activity WHERE field = 'status'", one=True)["c"] == 3


def test_bulk_update_rejects_bad_status_and_viewers(client):
    ref = db.query("SELECT ref FROM controls WHERE applicable = 1 LIMIT 1", one=True)["ref"]
    before = db.query("SELECT status FROM controls WHERE ref = ?", (ref,), one=True)["status"]
    post(client, "/controls/bulk", {"refs": [ref], "status": "Done!"})
    assert db.query("SELECT status FROM controls WHERE ref = ?", (ref,), one=True)["status"] == before
    as_role(client, "viewer")
    assert post(client, "/controls/bulk", {"refs": [ref], "status": "Verified"}).status_code == 403
    assert b"tick-all" not in client.get("/controls").data


def test_duplicate_risk_prefills_but_saves_nothing_until_create(client):
    src = db.query("SELECT * FROM risks WHERE id = 1", one=True)
    before = db.query("SELECT COUNT(*) c FROM risks", one=True)["c"]

    page = client.get("/risks/new?from=1").data
    assert f"Copy of {src['ref']}".encode() in page
    assert src["asset"].encode() in page
    assert db.query("SELECT COUNT(*) c FROM risks", one=True)["c"] == before

    form = {k: (str(src[k]) if src[k] is not None else "") for k in RISK_FORM}
    form["controls"] = app_module.linked_control_refs(1)
    post(client, "/risks/new?from=1", form)
    new = db.query("SELECT * FROM risks ORDER BY id DESC LIMIT 1", one=True)
    assert new["id"] != 1 and new["ref"] != src["ref"] and new["asset"] == src["asset"]
    assert sorted(app_module.linked_control_refs(new["id"])) == sorted(form["controls"])
    assert db.query("SELECT * FROM risks WHERE id = 1", one=True)["ref"] == src["ref"]


# ---- Phase 6: search, exports, readiness trend, print, dark mode ---------------------

import csv as _csv


def _csv_rows(resp):
    return list(_csv.reader(io.StringIO(resp.data.decode())))


def test_search_finds_across_registers(client):
    html = client.get("/search?q=backup").data
    assert b"A.8.13" in html                     # control "Information backup"
    assert b"result" in html
    assert b"Controls" in html


def test_search_by_reference_and_short_query(client):
    assert b"R-004" in client.get("/search?q=R-004").data
    assert b"at least 2 characters" in client.get("/search?q=a").data


def test_search_treats_wildcards_literally(client):
    # "%" would match everything if passed to LIKE unescaped.
    html = client.get("/search?q=%25%25").data
    assert b"Nothing matches" in html


def test_search_is_escaped(client):
    html = client.get("/search?q=<script>x</script>").data
    assert b"<script>x</script>" not in html


def test_search_needs_login(anon):
    assert anon.get("/search?q=backup").status_code == 302


@pytest.mark.parametrize("kind,first_col,count_sql", [
    ("risks", "Ref", "SELECT COUNT(*) c FROM risks"),
    ("documents", "Code", "SELECT COUNT(*) c FROM documents"),
    ("findings", "Ref", "SELECT COUNT(*) c FROM findings"),
])
def test_csv_exports(client, kind, first_col, count_sql):
    resp = client.get(f"/export/{kind}.csv")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["Content-Disposition"]
    rows = _csv_rows(resp)
    assert rows[3][0] == first_col                  # title, date, blank, header
    assert len(rows) - 4 == db.query(count_sql, one=True)["c"]


def test_risk_export_has_scores_and_links(client):
    rows = _csv_rows(client.get("/export/risks.csv"))
    header, first = rows[3], rows[4]
    record = dict(zip(header, first))
    assert int(record["Inherent score"]) == int(record["Likelihood"]) * int(record["Impact"])
    assert record["Controls"]                        # linked Annex A refs


def test_csv_blocks_formula_injection(client):
    post(client, "/risks/new", {**RISK_FORM, "asset": '=HYPERLINK("http://evil","x")'})
    rows = _csv_rows(client.get("/export/risks.csv"))
    assets = [r[1] for r in rows[4:]]
    assert "'=HYPERLINK(\"http://evil\",\"x\")" in assets
    assert not any(a.startswith("=") for a in assets)
    assert app_module.csv_cell("-2") == "'-2" and app_module.csv_cell(5) == 5


def test_unknown_export_is_404(client):
    assert client.get("/export/users.csv").status_code == 404


def test_soa_export_still_works(client):
    rows = _csv_rows(client.get("/soa/export.csv"))
    assert rows[3][0] == "Control" and len(rows) - 4 == 93


def test_dashboard_records_todays_readiness_and_draws_trend(client):
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    html = client.get("/").data
    snap = db.query("SELECT * FROM readiness_snapshots WHERE day = ?", (today,), one=True)
    assert snap["overall"] == db.readiness()["overall"]
    assert b"Overall readiness over time" in html
    assert b'class="trend-line"' in html and b"Show as a table" in html
    client.get("/")                                  # same day: replaced, not added
    assert db.query("SELECT COUNT(*) c FROM readiness_snapshots WHERE day = ?",
                    (today,), one=True)["c"] == 1


def test_trend_chart_geometry():
    rows = [{"day": "2025-01-01", "overall": 0, "controls": 0, "clauses": 0, "documents": 0},
            {"day": "2025-01-08", "overall": 100, "controls": 100, "clauses": 100, "documents": 100}]
    t = app_module.trend_chart(rows)
    assert t["points"][0]["y"] == t["baseline"]          # 0% sits on the baseline
    assert t["points"][1]["y"] == t["top"]               # 100% at the top
    assert t["points"][0]["x"] == t["left"] and t["points"][1]["x"] == t["right"]
    assert t["path"].startswith("M") and " L" in t["path"]


def test_soa_has_print_button_and_print_header(client):
    html = client.get("/soa").data
    assert b"window.print()" in html
    assert b"print-title" in html and b"printed by ISMS Admin" in html


def test_theme_toggle_and_dark_palette_present(client):
    html = client.get("/").data
    assert b'id="theme-toggle"' in html and b'localStorage' in html
    css = client.get("/static/css/style.css").data
    assert b':root[data-theme="dark"]' in css
