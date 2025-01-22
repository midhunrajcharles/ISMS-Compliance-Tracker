"""Create and populate the ISMS Compliance Tracker database.

Run once before starting the application:

    python seed.py

The Annex A control library is factual (ISO/IEC 27001:2022). The risks,
documents and audit findings are a realistic worked example for a mid-sized
software product company, modelled on the enterprise distribution-management
products built at the Sholinganallur development centre.
"""

import os
import random
from datetime import datetime, timedelta, timezone

import db
from annex_a import CONTROLS, CLAUSES

TODAY = db.TODAY
FMT = "%Y-%m-%d"


def d(offset_days):
    return (TODAY + timedelta(days=offset_days)).strftime(FMT)


# ---------------------------------------------------------------------------
# Controls whose status is fixed by hand so the worked example stays coherent
# with the risks and audit findings below.
# ---------------------------------------------------------------------------

PINNED_STATUS = {
    "A.5.1": "Verified",        # policy set approved by management
    "A.5.2": "Implemented",
    "A.5.9": "In Progress",     # asset register incomplete -> NC-006
    "A.5.12": "Implemented",
    "A.5.15": "Implemented",
    "A.5.18": "In Progress",    # access reviews not run -> NC-003
    "A.5.24": "In Progress",
    "A.5.30": "Not Started",
    "A.5.35": "Not Started",
    "A.6.1": "Implemented",
    "A.6.3": "In Progress",     # training at 68% -> NC-004
    "A.6.6": "Verified",        # NDAs signed by all staff
    "A.7.1": "Verified",
    "A.7.2": "Verified",
    "A.7.4": "Implemented",
    "A.7.7": "In Progress",
    "A.8.2": "In Progress",
    "A.8.4": "In Progress",     # source code access too broad -> R-001
    "A.8.5": "In Progress",     # MFA incomplete -> NC-005
    "A.8.8": "Not Started",     # no VAPT -> R-014
    "A.8.12": "Not Started",    # no DLP
    "A.8.13": "Implemented",    # backups run, restores untested -> NC-002
    "A.8.15": "Implemented",    # logs exist, not aggregated -> NC-007
    "A.8.16": "Not Started",
    "A.8.22": "Not Started",    # flat network -> R-012
    "A.8.25": "In Progress",
    "A.8.28": "In Progress",
    "A.8.29": "Not Started",
    "A.8.31": "In Progress",    # prod data in test -> NC-008 / R-011
    "A.8.33": "Not Started",
}

# Distribution of statuses per theme for the remaining controls, reflecting a
# certification programme roughly two months in: physical security was largely
# inherited from the managed office, technological controls lag furthest.
THEME_MIX = {
    "Organizational": ["Not Started"] * 3 + ["In Progress"] * 5 + ["Implemented"] * 3 + ["Verified"],
    "People":         ["In Progress"] * 3 + ["Implemented"] * 3 + ["Verified"],
    "Physical":       ["In Progress"] + ["Implemented"] * 4 + ["Verified"] * 3,
    "Technological":  ["Not Started"] * 5 + ["In Progress"] * 4 + ["Implemented"] * 3,
}

EXCLUSIONS = {
    "A.8.30": (
        "All development of the product suite is carried out in-house by the "
        "development centre at Sholinganallur. No software development activity "
        "is outsourced to third parties. This exclusion will be reassessed "
        "immediately if any development work is contracted out."
    ),
}

OWNERS = {
    "Organizational": "ISMS Manager",
    "People": "HR Manager",
    "Physical": "Admin / Facilities",
    "Technological": "IT Infrastructure Lead",
}

CLAUSE_STATUS = {
    "4.1": "Implemented", "4.2": "Implemented", "4.3": "Verified", "4.4": "In Progress",
    "5.1": "Implemented", "5.2": "Verified", "5.3": "Implemented",
    "6.1.1": "Implemented", "6.1.2": "Verified", "6.1.3": "In Progress",
    "6.2": "In Progress", "6.3": "Not Started",
    "7.1": "Implemented", "7.2": "In Progress", "7.3": "In Progress",
    "7.4": "In Progress", "7.5": "Implemented",
    "8.1": "In Progress", "8.2": "Implemented", "8.3": "In Progress",
    "9.1": "Not Started", "9.2": "Not Started", "9.3": "Not Started",
    "10.1": "Not Started", "10.2": "In Progress",
}

# ---------------------------------------------------------------------------
# code, title, type, version, owner, status, approved_on, next_review, clause
# ---------------------------------------------------------------------------

DOCUMENTS = [
    ("ISMS-SCP-01", "ISMS Scope Statement", "Policy", "1.0", "ISMS Manager",
     "Approved", d(-38), d(327), "4.3"),
    ("ISMS-POL-01", "Information Security Policy", "Policy", "1.1", "CEO",
     "Approved", d(-35), d(330), "5.2"),
    ("ISMS-POL-02", "Access Control Policy", "Policy", "1.0", "IT Infrastructure Lead",
     "Approved", d(-28), d(337), None),
    ("ISMS-POL-03", "Acceptable Use Policy", "Policy", "1.0", "HR Manager",
     "Approved", d(-28), d(337), None),
    ("ISMS-POL-04", "Cryptography and Key Management Policy", "Policy", "0.3",
     "IT Infrastructure Lead", "Draft", None, None, None),
    ("ISMS-POL-05", "Secure Development Policy", "Policy", "0.6", "Delivery Head",
     "Under Review", None, None, None),
    ("ISMS-POL-06", "Supplier and Cloud Security Policy", "Policy", "0.2", "ISMS Manager",
     "Draft", None, None, None),
    ("ISMS-POL-07", "Remote Working Policy", "Policy", "1.0", "HR Manager",
     "Approved", d(-21), d(344), None),
    ("ISMS-POL-08", "Clear Desk and Clear Screen Policy", "Policy", "1.0", "Admin / Facilities",
     "Approved", d(-21), d(344), None),
    ("ISMS-PRO-01", "Risk Assessment and Treatment Procedure", "Procedure", "1.0",
     "ISMS Manager", "Approved", d(-30), d(335), "6.1.2"),
    ("ISMS-PRO-02", "Information Security Incident Management Procedure", "Procedure",
     "0.8", "IT Infrastructure Lead", "Under Review", None, None, None),
    ("ISMS-PRO-03", "Access Provisioning and Review Procedure", "Procedure", "0.4",
     "IT Infrastructure Lead", "Draft", None, None, None),
    ("ISMS-PRO-04", "Change Management Procedure", "Procedure", "0.7", "Delivery Head",
     "Under Review", None, None, None),
    ("ISMS-PRO-05", "Backup and Restoration Procedure", "Procedure", "1.0",
     "IT Infrastructure Lead", "Approved", d(-24), d(341), None),
    ("ISMS-PRO-06", "Internal Audit Procedure", "Procedure", "0.2", "ISMS Manager",
     "Draft", None, None, "9.2"),
    ("ISMS-PRO-07", "Onboarding and Offboarding Procedure", "Procedure", "0.5",
     "HR Manager", "Under Review", None, None, None),
    ("ISMS-PLN-01", "Business Continuity and Disaster Recovery Plan", "Plan", "0.3",
     "Delivery Head", "Draft", None, None, None),
    ("ISMS-REG-01", "Statement of Applicability", "Register", "0.9", "ISMS Manager",
     "Under Review", None, None, "6.1.3"),
    ("ISMS-REG-02", "Information Asset Register", "Register", "1.2", "ISMS Manager",
     "Approved", d(-18), d(165), None),
    ("ISMS-REG-03", "Risk Register", "Register", "1.1", "ISMS Manager",
     "Approved", d(-16), d(167), "8.2"),
    ("ISMS-REG-04", "Legal and Regulatory Requirements Register", "Register", "0.4",
     "ISMS Manager", "Draft", None, None, None),
    ("ISMS-REC-01", "Security Awareness Training Records", "Record", "1.0", "HR Manager",
     "Approved", d(-12), d(171), "7.2"),
]

# Documents that evidence particular Annex A controls.
DOC_CONTROL_LINKS = {
    "ISMS-POL-01": ["A.5.1", "A.5.4"],
    "ISMS-POL-02": ["A.5.15", "A.5.18", "A.8.3"],
    "ISMS-POL-03": ["A.5.10", "A.8.1"],
    "ISMS-POL-04": ["A.8.24"],
    "ISMS-POL-05": ["A.8.25", "A.8.26", "A.8.28"],
    "ISMS-POL-06": ["A.5.19", "A.5.20", "A.5.23"],
    "ISMS-POL-07": ["A.6.7"],
    "ISMS-POL-08": ["A.7.7"],
    "ISMS-PRO-01": ["A.5.8"],
    "ISMS-PRO-02": ["A.5.24", "A.5.26", "A.6.8"],
    "ISMS-PRO-03": ["A.5.16", "A.5.18", "A.8.2"],
    "ISMS-PRO-04": ["A.8.32"],
    "ISMS-PRO-05": ["A.8.13"],
    "ISMS-PRO-07": ["A.5.11", "A.6.1", "A.6.5"],
    "ISMS-PLN-01": ["A.5.29", "A.5.30", "A.8.14"],
    "ISMS-REG-02": ["A.5.9", "A.5.12"],
    "ISMS-REG-04": ["A.5.31", "A.5.32", "A.5.34"],
    "ISMS-REC-01": ["A.6.3"],
}

# ---------------------------------------------------------------------------
# ref, asset, asset_type, threat, vulnerability, existing_controls,
# L, I, treatment, plan, resL, resI, owner, target, status, [control refs]
# ---------------------------------------------------------------------------

RISKS = [
    ("R-001", "Product source code repository", "Software",
     "Theft or leakage of intellectual property",
     "All developers hold write access to every repository; no branch protection or code-owner review",
     "Repository hosted on a private cloud account; VPN required",
     4, 5, "Modify",
     "Introduce least-privilege repository roles, enforce branch protection and mandatory peer review, "
     "and enable secret scanning on every push.",
     2, 5, "Delivery Head", d(75), "In Treatment", ["A.8.4", "A.8.2", "A.5.15"]),

    ("R-002", "Customer and distributor master data", "Information",
     "Unauthorised disclosure of client commercial data",
     "Database administrator credentials shared between three engineers; no per-user accounts",
     "Database reachable only from the application subnet",
     3, 5, "Modify",
     "Issue named administrator accounts, remove the shared credential, and enable query auditing.",
     2, 5, "IT Infrastructure Lead", d(60), "In Treatment", ["A.8.2", "A.5.16", "A.8.15"]),

    ("R-003", "Developer and consultant laptops", "Hardware",
     "Loss or theft of endpoint containing source code and client data",
     "Full disk encryption not enabled on machines issued before 2023",
     "Asset register maintained; devices password protected",
     3, 4, "Modify",
     "Enable BitLocker across the estate, verify via a monthly compliance report, and record encryption "
     "status in the asset register.",
     1, 4, "IT Infrastructure Lead", d(45), "In Treatment", ["A.8.1", "A.7.9", "A.8.24"]),

    ("R-004", "Field sales mobile application", "Software",
     "Interception of order and pricing data in transit",
     "Older released app versions permit fallback to unencrypted HTTP on poor connectivity",
     "Current release pins TLS 1.2",
     2, 4, "Modify",
     "Force minimum supported app version at the API gateway and remove the HTTP fallback path.",
     1, 4, "Delivery Head", d(90), "Open", ["A.8.24", "A.8.20", "A.5.14"]),

    ("R-005", "Production hosting environment", "Service",
     "Extended service outage affecting all client tenants",
     "Single availability zone deployment with no tested failover",
     "Daily snapshots retained for 30 days",
     2, 5, "Modify",
     "Deploy a warm standby in a second availability zone and test failover twice yearly.",
     1, 5, "IT Infrastructure Lead", d(150), "Open", ["A.8.14", "A.5.30", "A.8.6"]),

    ("R-006", "Corporate email accounts", "Service",
     "Credential theft through phishing leading to business email compromise",
     "Multi-factor authentication enforced for IT staff only",
     "Spam filtering enabled; annual awareness session delivered",
     4, 4, "Modify",
     "Enforce MFA for all users without exception and run quarterly simulated phishing exercises.",
     2, 4, "IT Infrastructure Lead", d(30), "In Treatment", ["A.8.5", "A.6.3", "A.5.17"]),

    ("R-007", "Production database backups", "Information",
     "Unrecoverable data loss following corruption or ransomware",
     "Backups are taken but restoration has never been tested end to end",
     "Automated nightly backup to object storage",
     2, 5, "Modify",
     "Perform and document a quarterly full restoration test into an isolated environment.",
     1, 5, "IT Infrastructure Lead", d(40), "In Treatment", ["A.8.13", "A.5.30"]),

    ("R-008", "Personally identifiable information held in CRM", "Information",
     "Regulatory penalty for non-compliant retention of personal data",
     "No defined retention period or deletion routine for contact records",
     "Access limited to the sales team",
     3, 4, "Modify",
     "Define a retention schedule aligned to the Digital Personal Data Protection Act 2023 and "
     "automate deletion beyond the retention window.",
     2, 3, "ISMS Manager", d(120), "Open", ["A.5.34", "A.8.10", "A.5.31"]),

    ("R-009", "Third-party libraries in the product build", "Software",
     "Supply chain compromise through a vulnerable or malicious dependency",
     "No software composition analysis in the build pipeline; dependency versions unpinned",
     "Dependencies reviewed manually at major release",
     3, 4, "Modify",
     "Add automated dependency scanning to the CI pipeline and fail the build on high-severity findings.",
     2, 4, "Delivery Head", d(85), "Open", ["A.8.8", "A.5.21", "A.8.25"]),

    ("R-010", "Accounts belonging to departed employees", "Information",
     "Unauthorised access to systems after an employee exits",
     "Offboarding checklist exists but revocation is not verified or evidenced",
     "HR notifies IT of exits by email",
     3, 4, "Modify",
     "Make access revocation a mandatory signed-off step in the offboarding procedure and reconcile "
     "active accounts against the HR roster monthly.",
     1, 4, "HR Manager", d(50), "In Treatment", ["A.5.11", "A.6.5", "A.5.18"]),

    ("R-011", "Development and test environments", "Service",
     "Exposure of live client data to staff with no business need",
     "Production data is copied unmasked into test environments for defect reproduction",
     "Test environments sit behind the corporate VPN",
     4, 4, "Modify",
     "Prohibit unmasked production data in non-production environments and provide a masked data "
     "generation utility to the engineering team.",
     2, 3, "Delivery Head", d(70), "In Treatment", ["A.8.31", "A.8.33", "A.8.11"]),

    ("R-012", "Office network at the development centre", "Service",
     "Lateral movement from an untrusted device onto corporate systems",
     "Guest wireless and corporate wired networks share a single flat VLAN",
     "Wireless access is pre-shared key protected",
     2, 3, "Modify",
     "Segregate guest, corporate and server traffic into separate VLANs with filtering between them.",
     1, 3, "IT Infrastructure Lead", d(110), "Open", ["A.8.22", "A.8.20", "A.8.21"]),

    ("R-013", "Privileged server accounts", "Information",
     "Misuse or compromise of administrative access",
     "Shared root credentials in use with no session logging or approval workflow",
     "Server access restricted to the internal network",
     3, 5, "Modify",
     "Introduce named privileged accounts with just-in-time elevation, and log and review all "
     "privileged sessions.",
     2, 4, "IT Infrastructure Lead", d(65), "In Treatment", ["A.8.2", "A.8.18", "A.8.15"]),

    ("R-014", "Customer-facing web portal", "Software",
     "Exploitation of a known application vulnerability",
     "No periodic vulnerability assessment or penetration test has been commissioned",
     "Code review performed before each release",
     3, 5, "Modify",
     "Commission an annual third-party VAPT and remediate findings on a tracked schedule; add "
     "automated scanning between assessments.",
     2, 5, "Delivery Head", d(100), "Open", ["A.8.8", "A.8.29", "A.8.26"]),

    ("R-015", "Printed documents at reception and desks", "Information",
     "Unauthorised disclosure of client information to visitors",
     "Clear desk rule published but not monitored; printouts left on shared printers",
     "Visitors escorted in working areas",
     2, 2, "Modify",
     "Introduce badge-release printing and include clear desk checks in the monthly facilities walk.",
     1, 2, "Admin / Facilities", d(80), "Open", ["A.7.7", "A.5.13", "A.7.10"]),

    ("R-016", "Server and communications room", "Hardware",
     "Unauthorised physical access to hosting equipment",
     "Door held open during maintenance visits; contractor access not logged",
     "Access card reader fitted; CCTV covers the corridor",
     2, 4, "Modify",
     "Require contractor sign-in with escort for the full visit and enable a door-ajar alert on the reader.",
     1, 4, "Admin / Facilities", d(55), "In Treatment", ["A.7.2", "A.7.3", "A.7.4"]),
]

# ---------------------------------------------------------------------------
# ref, source, raised_on, against, description, severity, root_cause,
# corrective_action, owner, due, status, closed_on
# ---------------------------------------------------------------------------

FINDINGS = [
    ("NC-001", "Gap Assessment", d(-20), "Clause 9.2",
     "No internal audit programme has been defined and no internal audit of the ISMS has been "
     "performed. Certification cannot proceed without at least one completed internal audit cycle.",
     "Major",
     "The certification programme prioritised policy drafting; assurance activities were not scheduled.",
     "Draft and approve an internal audit procedure, define a twelve-month audit programme, and "
     "complete a first full internal audit before the stage 1 assessment.",
     "ISMS Manager", d(70), "Open", None),

    ("NC-002", "Gap Assessment", d(-20), "A.8.13",
     "Nightly backups are running and monitored, but no evidence exists of a successful restoration "
     "test. An untested backup is not a demonstrated control.",
     "Minor",
     "Restoration testing was not included in the backup procedure when it was written.",
     "Amend the backup procedure to mandate quarterly restoration testing and retain signed test records.",
     "IT Infrastructure Lead", d(-5), "In Progress", None),

    ("NC-003", "Gap Assessment", d(-19), "A.5.18",
     "The access control policy requires a quarterly review of user access rights to production "
     "systems. No review has been carried out since the policy was approved.",
     "Minor",
     "No owner was assigned to the review activity and no calendar reminder was configured.",
     "Assign the review to the IT Infrastructure Lead, schedule it quarterly, and retain the signed "
     "review sheet as evidence.",
     "IT Infrastructure Lead", d(35), "In Progress", None),

    ("NC-004", "Gap Assessment", d(-19), "A.6.3",
     "Security awareness training completion stands at 68 per cent against a target of 95 per cent. "
     "Contract staff and recent joiners are largely unrecorded.",
     "Observation",
     "Training is delivered as a one-off annual session with no mechanism to capture later joiners.",
     "Move awareness training into the induction checklist and issue quarterly refresher modules with "
     "attendance tracked in the training record.",
     "HR Manager", d(60), "Open", None),

    ("NC-005", "Gap Assessment", d(-18), "A.8.5",
     "Multi-factor authentication is enforced for IT administrators but not for general staff "
     "accessing email and the CRM remotely.",
     "Major",
     "MFA rollout was scoped to privileged users only, on the assumption that general accounts held "
     "no sensitive data.",
     "Enforce MFA tenant-wide with no standing exemptions, and record any temporary exception with an "
     "expiry date and management approval.",
     "IT Infrastructure Lead", d(30), "In Progress", None),

    ("NC-006", "Gap Assessment", d(-17), "A.5.9",
     "The information asset register is missing a named owner for twelve entries, and four "
     "decommissioned servers remain listed as active.",
     "Minor",
     "The register was populated in a single exercise and has no defined maintenance cycle.",
     "Assign owners to all outstanding entries and add a monthly reconciliation step against the "
     "configuration inventory.",
     "ISMS Manager", d(25), "Closed", d(-3)),

    ("NC-007", "Gap Assessment", d(-16), "A.8.15",
     "Application and system logs are generated and retained locally, but are not centrally "
     "aggregated, which prevents correlation and timely detection.",
     "OFI",
     "Central log aggregation was deferred pending budget approval.",
     "Evaluate a central log management solution and present costed options at the next management review.",
     "IT Infrastructure Lead", d(140), "Open", None),

    ("NC-008", "Gap Assessment", d(-15), "A.8.31",
     "A copy of the live client database was found in the shared test environment, accessible to the "
     "full engineering team.",
     "Minor",
     "No approved method existed for producing realistic test data, so production data was copied.",
     "Purge the copied data, prohibit unmasked production data in test, and supply a masked data "
     "generation utility.",
     "Delivery Head", d(20), "Closed", d(-2)),
]


def build():
    if os.path.exists(db.DB_PATH):
        os.remove(db.DB_PATH)

    conn = db.connect()
    with open(db.SCHEMA_PATH, "r", encoding="utf-8") as fh:
        conn.executescript(fh.read())

    # User accounts (one demo login per role) and the activity history. First,
    # because the assignee columns in the other tables point at users.
    db.ensure_tables(conn)

    rng = random.Random(27001)          # fixed seed keeps the demo reproducible

    # ---- Annex A controls ------------------------------------------------
    for ref, theme, title, ctype, purpose in CONTROLS:
        applicable = 0 if ref in EXCLUSIONS else 1
        if applicable:
            status = PINNED_STATUS.get(ref) or rng.choice(THEME_MIX[theme])
            justification = "Relevant to the scope of the ISMS and to identified risks."
        else:
            status = "Not Started"
            justification = EXCLUSIONS[ref]
        conn.execute(
            """INSERT INTO controls
               (ref, theme, title, control_type, purpose, applicable,
                justification, status, owner, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (ref, theme, title, ctype, purpose, applicable, justification,
             status, OWNERS[theme], d(0)),
        )

    # ---- Clauses 4-10 ----------------------------------------------------
    for ref, title, requirement in CLAUSES:
        conn.execute(
            "INSERT INTO clauses (ref, title, requirement, status, owner) VALUES (?,?,?,?,?)",
            (ref, title, requirement, CLAUSE_STATUS.get(ref, "Not Started"), "ISMS Manager"),
        )

    # ---- Document register ----------------------------------------------
    for row in DOCUMENTS:
        conn.execute(
            """INSERT INTO documents
               (code, title, doc_type, version, owner, status, approved_on,
                next_review, clause_ref)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            row,
        )

    # ---- Risk register ---------------------------------------------------
    for r in RISKS:
        (ref, asset, atype, threat, vuln, existing, lk, im, treat, plan,
         rlk, rim, owner, target, status, control_refs) = r
        conn.execute(
            """INSERT INTO risks
               (ref, asset, asset_type, threat, vulnerability, existing_controls,
                likelihood, impact, treatment, treatment_plan, res_likelihood,
                res_impact, owner, target_date, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ref, asset, atype, threat, vuln, existing, lk, im, treat, plan,
             rlk, rim, owner, target, status, d(-22)),
        )
        risk_id = conn.execute("SELECT id FROM risks WHERE ref = ?", (ref,)).fetchone()["id"]
        for cref in control_refs:
            row = conn.execute("SELECT id FROM controls WHERE ref = ?", (cref,)).fetchone()
            if row:
                conn.execute(
                    "INSERT OR IGNORE INTO risk_controls (risk_id, control_id) VALUES (?,?)",
                    (risk_id, row["id"]),
                )

    # ---- Audit findings --------------------------------------------------
    for f in FINDINGS:
        conn.execute(
            """INSERT INTO findings
               (ref, source, raised_on, clause_or_control, description, severity,
                root_cause, corrective_action, owner, due_date, status, closed_on)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            f,
        )

    # ---- Document to control links --------------------------------------
    for code, refs in DOC_CONTROL_LINKS.items():
        doc = conn.execute("SELECT id FROM documents WHERE code = ?", (code,)).fetchone()
        if not doc:
            continue
        for cref in refs:
            ctl = conn.execute("SELECT id FROM controls WHERE ref = ?", (cref,)).fetchone()
            if ctl:
                conn.execute(
                    "INSERT OR IGNORE INTO doc_controls (document_id, control_id) VALUES (?,?)",
                    (doc["id"], ctl["id"]),
                )

    # ---- Derive Statement of Applicability justifications ----------------
    db.refresh_justifications(conn)

    # ---- Readiness history -----------------------------------------------
    # Illustrative: twelve weekly readings climbing towards today's score, so
    # the "readiness over time" chart has a story to show in a fresh demo.
    # Dated on the real calendar, like every reading the app takes itself.
    conn.commit()
    now = db.readiness()
    real_today = datetime.now(timezone.utc).date()
    for week in range(12, 0, -1):
        share = 1 - week * 0.055                      # 34% .. 94% of today's score
        conn.execute(
            """INSERT OR REPLACE INTO readiness_snapshots
               (day, overall, controls, clauses, documents) VALUES (?,?,?,?,?)""",
            ((real_today - timedelta(weeks=week)).strftime(FMT),
             round(now["overall"] * share, 1),
             round(now["controls"]["percent"] * share, 1),
             round(now["clauses"]["percent"] * min(1, share + 0.1), 1),
             round(now["documents"]["percent"] * min(1, share + 0.2), 1)),
        )

    # ---- Assign work to the demo people so "My tasks" has something in it --
    # Ravi takes what the IT Infrastructure Lead owns; the ISMS Admin takes
    # what the ISMS Manager owns. Open controls get staggered due dates, a
    # few of them already overdue.
    for owner, email in (("IT Infrastructure Lead", "editor@example.com"),
                         ("ISMS Manager", "admin@example.com")):
        uid = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]
        for table in ("risks", "findings"):
            conn.execute(f"UPDATE {table} SET assignee_id = ? WHERE owner = ?", (uid, owner))
        open_controls = conn.execute(
            """SELECT id FROM controls
               WHERE owner = ? AND applicable = 1
                 AND status IN ('Not Started', 'In Progress')
               ORDER BY id""",
            (owner,),
        ).fetchall()
        for i, row in enumerate(open_controls):
            conn.execute(
                "UPDATE controls SET assignee_id = ?, due_date = ? WHERE id = ?",
                (uid, d(-12 + (i * 11) % 90), row["id"]),
            )
    conn.commit()

    conn.commit()

    counts = {
        t: conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]
        for t in ("controls", "clauses", "documents", "risks", "findings",
                  "risk_controls", "doc_controls", "users", "activity",
                  "readiness_snapshots")
    }
    conn.close()

    print(f"Database created at {db.DB_PATH}")
    for table, n in counts.items():
        print(f"  {table:<15} {n:>4} rows")
    print(f"\nOverall readiness: {db.readiness()['overall']}%")


if __name__ == "__main__":
    build()
