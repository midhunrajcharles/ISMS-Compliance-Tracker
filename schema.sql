-- ============================================================================
--  ISMS Compliance Tracker - relational schema
--  ISO/IEC 27001:2022 Information Security Management System
-- ============================================================================

PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS doc_controls;
DROP TABLE IF EXISTS risk_controls;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS risks;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS clauses;
DROP TABLE IF EXISTS controls;

-- ---------------------------------------------------------------- controls
-- The 93 Annex A controls. One row per control, carrying both the
-- applicability decision (which feeds the Statement of Applicability)
-- and the implementation status (which feeds the readiness score).
CREATE TABLE controls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ref           TEXT    NOT NULL UNIQUE,          -- 'A.5.1'
    theme         TEXT    NOT NULL,                 -- Organizational|People|Physical|Technological
    title         TEXT    NOT NULL,
    control_type  TEXT,                             -- Preventive|Detective|Corrective
    purpose       TEXT,
    applicable    INTEGER NOT NULL DEFAULT 1,       -- 1 = in scope, 0 = excluded
    justification TEXT,                             -- required by clause 6.1.3(d)
    status        TEXT    NOT NULL DEFAULT 'Not Started',
                                                    -- Not Started|In Progress|Implemented|Verified
    owner         TEXT,
    evidence      TEXT,                             -- reference to evidence held
    notes         TEXT,
    updated_at    TEXT,
    assignee_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
                                                    -- the person doing the work
    due_date      TEXT
);

CREATE INDEX idx_controls_theme  ON controls(theme);
CREATE INDEX idx_controls_status ON controls(status);

-- ----------------------------------------------------------------- clauses
-- Mandatory clauses 4-10 of ISO/IEC 27001:2022. Certification is not
-- possible on Annex A alone; the clause requirements must also be met.
CREATE TABLE clauses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ref         TEXT    NOT NULL UNIQUE,            -- '6.1.2'
    title       TEXT    NOT NULL,
    requirement TEXT,
    status      TEXT    NOT NULL DEFAULT 'Not Started',
    owner       TEXT,
    notes       TEXT
);

-- --------------------------------------------------------------- documents
-- The ISMS document register: policies, procedures, plans and records,
-- with version control and a review cycle.
CREATE TABLE documents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    code         TEXT    NOT NULL UNIQUE,           -- 'ISMS-POL-01'
    title        TEXT    NOT NULL,
    doc_type     TEXT,                              -- Policy|Procedure|Plan|Register|Record
    version      TEXT    DEFAULT '0.1',
    owner        TEXT,
    status       TEXT    DEFAULT 'Draft',           -- Draft|Under Review|Approved|Obsolete
    approved_on  TEXT,
    next_review  TEXT,
    clause_ref   TEXT,                              -- clause that mandates it, if any
    notes        TEXT
);

-- ------------------------------------------------------------------- risks
-- Risk register implementing the 5x5 likelihood/impact model required by
-- clauses 6.1.2 and 8.2. Inherent and residual scores are both held so the
-- effect of treatment is measurable.
CREATE TABLE risks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ref               TEXT    NOT NULL UNIQUE,      -- 'R-001'
    asset             TEXT    NOT NULL,
    asset_type        TEXT,                         -- Information|Software|Hardware|Service|People
    threat            TEXT,
    vulnerability     TEXT,
    existing_controls TEXT,
    likelihood        INTEGER NOT NULL DEFAULT 3    CHECK (likelihood BETWEEN 1 AND 5),
    impact            INTEGER NOT NULL DEFAULT 3    CHECK (impact     BETWEEN 1 AND 5),
    treatment         TEXT    DEFAULT 'Modify',     -- Modify|Retain|Avoid|Share
    treatment_plan    TEXT,
    res_likelihood    INTEGER CHECK (res_likelihood BETWEEN 1 AND 5),
    res_impact        INTEGER CHECK (res_impact     BETWEEN 1 AND 5),
    owner             TEXT,
    target_date       TEXT,
    status            TEXT    DEFAULT 'Open',       -- Open|In Treatment|Closed
    created_at        TEXT,
    assignee_id       INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_risks_status ON risks(status);

-- ---------------------------------------------------------------- findings
-- Internal audit nonconformities and the corrective action (CAPA) cycle
-- required by clauses 9.2 and 10.2.
CREATE TABLE findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ref               TEXT    NOT NULL UNIQUE,      -- 'NC-001'
    source            TEXT,                         -- Internal Audit|Management Review|Incident
    raised_on         TEXT,
    clause_or_control TEXT,                         -- what it was raised against
    description       TEXT    NOT NULL,
    severity          TEXT    DEFAULT 'Minor',      -- Major|Minor|Observation|OFI
    root_cause        TEXT,
    corrective_action TEXT,
    owner             TEXT,
    due_date          TEXT,
    status            TEXT    DEFAULT 'Open',       -- Open|In Progress|Closed
    closed_on         TEXT,
    assignee_id       INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- ------------------------------------------------------- junction tables
-- A risk is mitigated by many controls; a control mitigates many risks.
CREATE TABLE risk_controls (
    risk_id    INTEGER NOT NULL REFERENCES risks(id)    ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    PRIMARY KEY (risk_id, control_id)
);

-- A document provides evidence for many controls; a control is evidenced
-- by many documents.
CREATE TABLE doc_controls (
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    control_id  INTEGER NOT NULL REFERENCES controls(id)  ON DELETE CASCADE,
    PRIMARY KEY (document_id, control_id)
);

-- ------------------------------------------ users, activity, comments, files
-- These tables are defined in db.py (USERS_SQL, ACTIVITY_SQL, COMMENTS_SQL,
-- EVIDENCE_SQL, SNAPSHOTS_SQL) and created on start-up, so databases built before those
-- features existed also gain them.
