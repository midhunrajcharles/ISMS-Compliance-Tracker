# ISMS Compliance Tracker

A web application for managing an **ISO/IEC 27001:2022** Information Security
Management System.

Built following an internship at Amshuhu iTech Solution Pvt. Ltd., Chennai,
where the organisation's ISO 27001 certification programme was being tracked
across a set of spreadsheets and word-processor documents. This application
replaces that arrangement with a single relational system in which the control
register, the risk register, the document register and the audit log all
reference one another.

---

## What it does

| Module | Purpose |
| --- | --- |
| **Dashboard** | Weighted certification-readiness score, control status breakdown, progress by theme, highest-exposure risks, overdue corrective actions |
| **Annex A controls** | All 93 controls of ISO/IEC 27001:2022 with status, owner, evidence, applicability and justification |
| **Clauses 4–10** | The mandatory management-system requirements, which Annex A alone does not satisfy |
| **Risk register** | 5×5 likelihood/impact assessment with inherent and residual scoring, treatment decisions and a heat map |
| **Document register** | ISMS policies, procedures and records with version control and review scheduling |
| **Statement of Applicability** | Generated live from the control register; exportable to CSV |
| **Audit & corrective action** | Nonconformities with root-cause analysis and CAPA tracking |
| **Gap analysis** | Everything currently blocking certification, ranked by consequence |

## Running it

```bash
pip install -r requirements.txt
python seed.py
python app.py
```

Then open <http://127.0.0.1:5000> and log in.

### Demo accounts

Every page needs a login. There is no public sign-up: the admin creates
accounts on the **Users** page. One demo account exists for each role:

| Role | Email | Password | May change |
|---|---|---|---|
| admin | `admin@example.com` | `admin123` | Everything, including user accounts |
| editor | `editor@example.com` | `demo1234` | Controls, clauses, risks, documents, findings |
| auditor | `auditor@example.com` | `demo1234` | Audit findings only |
| viewer | `viewer@example.com` | `demo1234` | Nothing (read only, e.g. the external auditor) |

These are for the demo only. Change or remove them before any real use.

Log in as the editor to see **My tasks** with overdue items: a fresh
`python seed.py` assigns the IT Infrastructure Lead's open work to Ravi and
the ISMS Manager's to the admin. An older `isms.db` is upgraded in place on
start-up (new tables and columns are added, nothing is deleted), but it starts
with nothing assigned.

Set a `SECRET_KEY` environment variable (on Vercel, in the project settings).
It signs the login cookie; without it a random key is used and everyone is
logged out whenever the app restarts.

### Tests

```bash
pip install pytest
pytest
```

`seed.py` creates `isms.db` and loads the full Annex A control library together
with a worked example: 16 risks, 22 documents and 8 audit findings for a
mid-sized software product company. Re-running it rebuilds the database from
scratch.

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
generated from the risks it treats and the documents that evidence it, so the
Statement of Applicability cannot drift out of step with the risk register.

## Schema

Seven tables. `controls`, `clauses`, `documents`, `risks` and `findings` carry
the domain data; `risk_controls` and `doc_controls` are junction tables
resolving the many-to-many relationships between a risk and the controls that
treat it, and between a document and the controls it evidences.

See `schema.sql`.

## Layout

```
isms-tracker/
├── app.py            Flask routes and request handling
├── db.py             Data access, risk scoring, readiness statistics
├── annex_a.py        The 93 Annex A controls and clauses 4–10
├── schema.sql        Relational schema
├── seed.py           Database creation and worked example
├── test_app.py       pytest suite (runs on a throwaway database)
├── uploads/          Evidence files, created on first upload (not in git)
├── templates/        Jinja2 templates
└── static/css/       Stylesheet
```

## Scope and limitations

This is a working prototype built as an academic project, not production
software. It now has logins with four roles (A.5.15 access control), password
hashing and CSRF protection on every form, and an activity history that
records who changed which field, from what, to what, and when. People can
comment on controls, risks and findings, and upload evidence files (PDF, PNG,
JPG, TXT, CSV, up to 10 MB; the content is checked, not just the extension)
to a control. There is a global search, CSV export of every register, a
readiness-over-time chart, a print-ready Statement of Applicability, and a
dark mode. Uploads are kept in `uploads/`; on Vercel the disk is wiped, so
there they are temporary. It still has no login rate limiting, and it is
single-tenant. Justification text that the app re-derives by itself is not
logged, because no person made that change.

## Reference

ISO/IEC 27001:2022, *Information security, cybersecurity and privacy
protection — Information security management systems — Requirements*, and
ISO/IEC 27002:2022, which provides the implementation guidance and the control
attributes used here.
