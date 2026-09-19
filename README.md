# ISMS Compliance Tracker

A web application for running an **ISO/IEC 27001:2022** Information Security
Management System: the Annex A control library, the risk register, the document
register, the Statement of Applicability, and the internal audit and corrective
action cycle — with logins, roles, an audit trail and evidence files.

Built following an internship at Amshuhu iTech Solution Pvt. Ltd., Chennai,
where the organisation's ISO 27001 certification programme was being tracked
across a set of spreadsheets and word-processor documents. This application
replaces that arrangement with a single relational system in which the control
register, the risk register, the document register and the audit log all
reference one another.

Flask + SQLite, no ORM, no JavaScript framework, no CDN.

---

## What it does

| Module | Purpose |
| --- | --- |
| **Dashboard** | Weighted certification-readiness score, readiness-over-time chart, recent activity, control status breakdown, progress by theme, highest-exposure risks, overdue corrective actions |
| **Annex A controls** | All 93 controls of ISO/IEC 27001:2022 with status, owner, assignee, due date, evidence files, applicability and justification; bulk status update from the list |
| **Clauses 4–10** | The mandatory management-system requirements, which Annex A alone does not satisfy |
| **Risk register** | 5×5 likelihood/impact assessment with inherent and residual scoring, treatment decisions, a heat map, and duplication of an existing risk |
| **Document register** | ISMS policies, procedures and records with version control, review scheduling and archiving |
| **Statement of Applicability** | Generated live from the control register; exportable to CSV and printable to PDF |
| **Audit & corrective action** | Nonconformities with root-cause analysis and CAPA tracking |
| **Gap analysis** | Everything currently blocking certification, ranked by consequence |
| **My tasks** | Per-person to-do list of assigned controls, risks and findings, soonest due first, with an overdue badge |
| **Activity** | Who changed what, from what, to what, and when — per record and across the whole system |
| **Comments & evidence** | Discussion on any control, risk or finding; proof files attached to a control |
| **Search** | One box across controls, risks, documents and findings |
| **Users** | Admin-managed accounts and roles (there is no public sign-up) |

### Roles

Everyone signed in can read everything; the role decides what may be changed.

| Role | May change | Typical holder |
| --- | --- | --- |
| `admin` | Everything, including accounts and deletions | Compliance lead |
| `editor` | Controls, clauses, risks, documents, findings, evidence | Control owners (IT, HR, dev lead) |
| `auditor` | Audit findings and comments only | Internal auditor |
| `viewer` | Nothing | External certification auditor, management |

## Running it

```bash
pip install -r requirements.txt
python seed.py          # builds isms.db with the control library and a worked example
python app.py
```

Then open <http://127.0.0.1:5000> and log in.

### Demo accounts

| Role | Email | Password |
|---|---|---|
| admin | `admin@example.com` | `admin123` |
| editor | `editor@example.com` | `demo1234` |
| auditor | `auditor@example.com` | `demo1234` |
| viewer | `viewer@example.com` | `demo1234` |

These exist for the demo only — change or remove them before any real use.
A fresh `python seed.py` also assigns the IT Infrastructure Lead's open work to
the editor account and the ISMS Manager's to the admin, so **My tasks** and the
overdue badge have something in them.

An existing `isms.db` from an earlier version is **upgraded in place** on
start-up: missing tables and columns are added, nothing is deleted. Such a
database starts with nothing assigned and no readiness history.

### Configuration

| Variable | Effect |
|---|---|
| `SECRET_KEY` | Signs the login cookie. Without it a random key is generated at start-up, so everyone is logged out whenever the app restarts. Set it in production (on Vercel, in the project settings). |
| `ISMS_DB_PATH` | Database location. Defaults to `isms.db` beside the code, or `/tmp/isms.db` on Vercel. |
| `ISMS_UPLOAD_DIR` | Evidence file location. Defaults to `uploads/`, or `/tmp/uploads` on Vercel. |
| `PORT` | Port to listen on (default 5000). |

### Tests

```bash
pip install pytest
pytest
```

96 tests covering every page, the permission rules for each role, CSRF, upload
validation, the activity trail, the readiness maths and the CSV exports. They
run against a throwaway database in a temporary folder, so the real `isms.db`
and `uploads/` are never touched.

## How a request is handled

```
browser  →  gatekeeper  →  route (app.py)  →  data access (db.py)  →  SQLite
                                  ↓
                         Jinja template  →  HTML
```

A single `before_request` gatekeeper runs in front of every page and checks
three things: is the caller signed in, is a POST carrying the session's CSRF
token, and does the caller's role permit this endpoint. One gate rather than a
per-route decorator means a newly added route cannot be left unprotected by
accident.

Every save compares the stored row with the submitted values and records **only
the fields that changed** in the `activity` table, with the user, the old value,
the new value and a UTC timestamp.

## Design notes

**No external dependencies beyond Flask.** Data access uses the standard
library `sqlite3` module directly rather than an ORM, so the SQL behind every
screen is visible. Charts are hand-drawn SVG and the stylesheet is written from
scratch — there is no CDN, no web font and no JavaScript framework, so the
application renders identically with no network connection.

**Readiness scoring.** Controls are weighted by status: verified 100%,
implemented 80%, in progress 40%, not started 0%. A control counts in full only
once its operation has been independently verified, which mirrors how a
certification auditor treats evidence. The overall figure blends controls (60%),
clause requirements (20%) and document approval (20%).

**Excluded controls are not counted as incomplete.** A control ruled out of
scope in the Statement of Applicability, with justification, cannot be
"unfinished" — so the denominator is applicable controls only.

**Justifications are derived, not typed.** Each control's SoA justification is
generated from the risks it treats and the documents that evidence it, and is
re-derived after every relevant save, so the Statement of Applicability cannot
drift out of step with the risk register. A justification written by hand is
recognised and left alone.

**Owner and assignee are different things.** ISO allows a control owner to be a
role ("IT Infrastructure Lead"), so that text field stays; `assignee_id` points
at the person who actually has the task and drives **My tasks**.

**The history survives deletion.** Deleting a risk, document or finding removes
the record and its comments, but its activity entries remain and a "deleted"
entry is added. An audit trail that loses entries when records are deleted is
not an audit trail.

**Dates.** Deadlines and overdue calculations run against a pinned demo date
(`db.TODAY`, 23 January 2025) so the worked example always reads the same way.
Activity timestamps and readiness snapshots use the real clock, because
"2h ago" must be true.

## Security

| Measure | Where |
|---|---|
| Passwords stored as `werkzeug` scrypt hashes, never in plain text | `db.ensure_tables`, `/profile`, `/users` |
| Session cookie signed with `SECRET_KEY`; `HttpOnly`, `SameSite=Lax`, `Secure` when hosted | `app.py` config |
| CSRF token required on every POST | `gatekeeper()` |
| Role checks enforced server-side, not only by hiding buttons | `can_write()` |
| Login returns the same message for an unknown email and a wrong password | `/login` |
| `?next=` only followed when it stays on this site | `safe_next()` |
| Uploads: allow-list of types, 10 MB cap, content signature checked, stored under a random name, served with `nosniff` | `check_upload()`, `/evidence/<id>` |
| CSV cells beginning `= + - @` are prefixed with `'` so spreadsheets cannot execute them | `csv_cell()` |
| SQL always parameterised; LIKE wildcards in search input escaped | `db.py`, `like_pattern()` |

Not implemented: rate limiting on failed logins, and multi-factor
authentication.

## Schema

`controls`, `clauses`, `documents`, `risks` and `findings` carry the domain
data; `risk_controls` and `doc_controls` are junction tables resolving the
many-to-many relationships between a risk and the controls that treat it, and
between a document and the controls it evidences. `users`, `activity`,
`comments`, `evidence_files` and `readiness_snapshots` support the application
layer and are created (or added to an older database) on start-up.

See `schema.sql` and the `*_SQL` constants in `db.py`.

## Layout

```
isms-tracker/
├── app.py            Flask routes, permissions, request handling
├── db.py             Data access, risk scoring, readiness statistics, history
├── annex_a.py        The 93 Annex A controls and clauses 4–10
├── schema.sql        Relational schema
├── seed.py           Database creation and worked example
├── test_app.py       pytest suite (runs on a throwaway database)
├── uploads/          Evidence files, created on first upload (not in git)
├── templates/        Jinja2 templates
└── static/css/       Stylesheet (light and dark themes)
```

## Deployment

`vercel.json` deploys the app as a serverless function. Two caveats there: the
filesystem is wiped on cold starts, so accounts created at runtime and uploaded
evidence do not persist (the seeded demo accounts are rebuilt each time), and
`SECRET_KEY` must be set in the project settings. For a persistent deployment,
run it on a host with a durable disk (Render, Railway, PythonAnywhere) or move
the database to PostgreSQL.

## Scope and limitations

A working prototype built as an academic project, not production software.
It is single-tenant, backed by a single SQLite file, and has no login rate
limiting or MFA. The risks, documents, findings, owners and control statuses
shipped in `seed.py` are an illustrative worked example for a fictional
mid-sized software product company — only the Annex A control library and the
clause requirements are drawn from the standard itself.

## Reference

ISO/IEC 27001:2022, *Information security, cybersecurity and privacy
protection — Information security management systems — Requirements*, and
ISO/IEC 27002:2022, which provides the implementation guidance and the control
attributes used here.
