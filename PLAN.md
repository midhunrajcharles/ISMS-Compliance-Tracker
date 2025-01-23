# Plan: make the ISMS Tracker more "performable"

Goal: give people more things they can **do** in the app, not just look at.
Today you can view, search, add and edit. You cannot log in, delete, comment,
upload proof, see who changed what, or get a personal to-do list.

Each phase works on its own. Finish one, test it, then start the next.
No new libraries are needed except where noted. Flask already ships
`werkzeug`, which has safe password hashing.

---

## Phase 0: Fix what breaks (small, do first) — ✅ done (2026-09-18)

| # | Task | Where |
|---|---|---|
| 0.1 | Show a friendly message instead of crashing when a document code already exists | `app.py` `document_form()`: catch `sqlite3.IntegrityError` |
| 0.2 | Check likelihood/impact are 1–5 on the server before saving a risk | `app.py` `risk_form()` |
| 0.3 | Make SoA justifications update live when risks or documents change | Move the loop from `seed.py` into `db.refresh_justifications()`; call it after saves |
| 0.4 | Put `TODAY` in one place (`db.py`) so `app.py` and `seed.py` can't disagree | `db.py`, `app.py`, `seed.py` |
| 0.5 | Delete the stale nested `isms-tracker/isms-tracker/` folder | filesystem |
| 0.6 | Add `test_app.py` (pytest + Flask test client on a temp DB) | new file |

**Done when:** no 500 errors from bad input, and `pytest` passes.

---

## Phase 1: Login and user accounts (the "Instagram login") — ✅ done (2026-09-18)

What users can do after this phase:
- **Log in / log out**
- **Admin creates accounts** for team members (no public sign-up: it's a company tool)
- **Change own password**
- See their **name in the top corner**

Build:
- New table `users (id, name, email UNIQUE, password_hash, role, created_at)`
- Roles: `admin` (everything), `editor` (add/edit), `auditor` (findings only), `viewer` (read only, e.g. the external auditor)
- One `before_request` gate in front of every page (can't be forgotten on a new route); a role that can't save gets 403 and doesn't see Save buttons
- CSRF token in every form
- Pages: `/login`, `/logout`, `/users` (admin), `/profile`
- Demo accounts, one per role: `admin@example.com` / `admin123`, and `editor@`, `auditor@`, `viewer@example.com` / `demo1234`
- Set `app.secret_key` from the `SECRET_KEY` env var

**Why it matters:** the README itself says an ISMS tool with no access
control would fail control A.5.15. This fixes the project's biggest weakness.

---

## Phase 2: Activity history (who changed what) — ✅ done (2026-09-18)

What users can do:
- See an **activity feed** on the dashboard: "Priya set A.8.13 to Verified · 2h ago"
- Open any control or risk and see its **full change history**

Build:
- New table `activity (id, user_id, entity_type, entity_ref, action, old_value, new_value, at)`
- Helpers `db.log()` and `db.log_update()` (logs only the fields that changed) called from every save, including users and passwords (never the password itself)
- Dashboard panel "Recent activity", a full `/activity` page, and a "History" card on control, risk, document and finding pages
- Times use the real clock ("2h ago"); `TODAY` stays pinned for deadlines only

**Why it matters:** auditors ask "who approved this and when?". Right now nobody can answer.

---

## Phase 3: My tasks and assignments — ✅ done (2026-09-18)

What users can do:
- **Assign** a control, risk or finding to a person (pick from the user list, not free text)
- Open **"My tasks"**: everything assigned to me, sorted by due date
- See a **red badge** in the sidebar with the number of overdue items

Build:
- ~~Change `owner` into `owner_id`~~ Changed approach: keep `owner` (the accountable *role*, which ISO allows) and add `assignee_id` → `users.id` (the *person* doing the work) to controls, risks and findings. No re-seed needed.
- Add `due_date` to controls
- Old databases are upgraded on start-up (`db.ADDED_COLUMNS`), nothing deleted
- New page `/my-tasks` (and `?user=` to see a colleague's list); badge count via `context_processor`
- A control leaves the list once it is Implemented; verifying it is the auditor's job

---

## Phase 4: Comments and evidence upload — ✅ done (2026-09-18)

What users can do:
- **Comment** on any control, risk or finding ("Waiting on IT for the backup test")
- **Upload proof files** (PDF, screenshot, log export) to a control
- **Download / preview** the proof later
- Evidence shows the uploader and date

Build:
- Table `comments (id, user_id, entity_type, entity_ref, body, at)`
- Table `evidence_files (id, control_id, filename, stored_path, size, uploaded_by, at)`
- Save files under `uploads/` with random names; allow only pdf/png/jpg/txt/csv; max 10 MB
- File content is checked against its type (a renamed program is refused); files are served with `nosniff`
- Who: editors and admins upload; the uploader or an admin can delete; auditors can comment too; viewers only read
- Note: on Vercel the disk is temporary, so uploads only persist when run locally (the page says so on Vercel)

---

## Phase 5: Delete, archive and bulk actions — ✅ done (2026-09-18)

What users can do:
- **Delete** a risk, document or finding (admin only, with a "are you sure?" step)
- **Archive** instead of delete for documents (status `Obsolete` already exists)
- **Bulk update**: tick several controls, then set all to "In Progress" at once
- **Duplicate** a risk as a starting point for a similar one

Build:
- `/delete/<kind>/<id>`: GET is the "are you sure?" page (shows what else goes), POST deletes; admin only. `ON DELETE CASCADE` cleans link tables; comments go too; the activity history is **kept**, plus a "deleted" entry
- Archive = status Obsolete (editors can); archived documents are hidden from the register unless "Show archived"
- Checkboxes + one form on `/controls` (editors and admins); excluded controls can't be ticked
- Duplicate = `/risks/new?from=<id>`: a pre-filled new-risk form; nothing is saved until Create

---

## Phase 6: Nicer to use — ✅ done (2026-09-18)

What users can do:
- **Global search** box: search controls, risks, documents and findings together
- **Export** risks, documents and findings to CSV (not only the SoA)
- **Readiness over time** chart: see the score climb week by week
- **Printable** SoA page (print stylesheet), so the auditor gets a clean PDF via the browser
- **Dark mode** toggle

Build:
- `/search?q=` route running four LIKE queries (wildcards escaped); search box at the top of the sidebar
- `/export/<risks|documents|findings>.csv`; every CSV cell that starts with `= + - @` is prefixed with `'` so spreadsheets can't run it as a formula
- Table `readiness_snapshots (day, overall, controls, clauses, documents)`, one row per real day (upserted when the dashboard opens); the seed adds 12 illustrative weekly readings; hand-drawn SVG line chart with hover tooltip and a table view
- "Print / save as PDF" on the SoA; `@media print`: A4 landscape, repeating headers, no split rows, print-only title block
- Dark mode: toggle in the sidebar (saved per browser, defaults to the system setting); all colours are CSS tokens; print always uses light

---

## Suggested order and size

| Phase | Size | Demo value |
|---|---|---|
| 0: Fixes | Small (half a day) | Stops embarrassing crashes |
| 1: Login | Medium (1–2 days) | ★★★ Biggest upgrade; fixes the README's own warning |
| 2: Activity history | Small–Medium | ★★★ Makes it feel "alive" |
| 3: My tasks | Medium | ★★ |
| 4: Comments + uploads | Medium | ★★ |
| 5: Delete / bulk | Small | ★ |
| 6: Extras | Pick and choose | ★ |

**Recommended minimum for a strong demo: Phases 0, 1 and 2.**

## Things to decide before starting

1. Keep deploying to Vercel? Its database resets on every cold start, so accounts
   and uploads would vanish. For a real demo with logins, run locally or move to
   a host with a persistent disk (Render, Railway, PythonAnywhere).
2. Keep `TODAY` pinned to 23 Jan 2025 for the demo, or switch to the real date?
3. Do you want sign-up for anyone, or admin-created accounts only (recommended)?
