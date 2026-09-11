"""
database.py — SQLite database initialization and connection management.

All 13 tables are created here with CREATE TABLE IF NOT EXISTS.
Every table has: id (UUID TEXT PK), created_at, updated_at.

Decision log:
- Raw sqlite3 over SQLAlchemy/ORM to keep the prototype dependency-light and
  give us full control over the schema without migration overhead.
- All complex structured data (JSON arrays, nested objects) stored as TEXT JSON
  columns. Pydantic handles serialization/deserialization at the service layer.
- Fingerprint column is INDEXED on normalized_findings for fast dedup lookups.
- threat_intelligence uses cve_id as PK (not UUID) since CVE IDs are the natural key.
"""

import sqlite3
from contextlib import contextmanager
from src.app.config import settings


def get_connection() -> sqlite3.Connection:
    """
    Open and return a new SQLite connection.
    Row factory set to sqlite3.Row for dict-like row access by column name.
    Caller is responsible for closing the connection.
    """
    conn = sqlite3.connect(settings.database_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # Write-Ahead Logging for better concurrency
    conn.execute("PRAGMA foreign_keys=ON")     # Enforce FK constraints
    return conn


@contextmanager
def get_db():
    """
    Context manager yielding a SQLite connection.
    Commits on success, rolls back on exception, always closes.

    Usage:
        with get_db() as db:
            db.execute("SELECT ...")
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Table creation SQL statements
# Grouped by pipeline stage for readability.
# ─────────────────────────────────────────────────────────────────────────────

_TABLES = [

    # ── Stage 1: Ingestion ───────────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS scanner_findings (
        -- Primary identity
        finding_id          TEXT PRIMARY KEY,   -- UUID, system-generated
        source_scanner      TEXT NOT NULL,       -- nessus|burp|zap|snyk|trivy|sarif|manual
        source_finding_id   TEXT,                -- scanner's own ID (nullable)
        ingestion_batch_id  TEXT NOT NULL,       -- UUID grouping this upload/POST

        -- Raw data (immutable after insert)
        raw_data            TEXT NOT NULL,       -- JSON string of original record
        raw_data_hash       TEXT NOT NULL,       -- SHA-256 of raw_data (integrity)

        -- Status
        status              TEXT NOT NULL DEFAULT 'received',
            -- received | processing | normalized | rejected

        -- Timestamps
        ingested_at         TEXT NOT NULL,       -- ISO 8601
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_scanner_findings_batch
        ON scanner_findings (ingestion_batch_id)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_scanner_findings_scanner
        ON scanner_findings (source_scanner)
    """,

    # ── Stage 1: Normalization ────────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS normalized_findings (
        -- Links 1:1 to scanner_findings
        finding_id              TEXT PRIMARY KEY REFERENCES scanner_findings(finding_id),

        -- Deduplication key — indexed for fast lookups
        fingerprint             TEXT NOT NULL,
            -- SHA-256(cwe_primary|canonical_path|parameter_class)

        -- Normalization outcome
        normalization_status    TEXT NOT NULL,
            -- normalized | normalized_with_warnings | rejected
        completeness_score      REAL NOT NULL DEFAULT 0.0,  -- 0.0–1.0
        normalization_warnings  TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
        normalization_errors    TEXT NOT NULL DEFAULT '[]', -- JSON array of strings

        -- Full canonical finding (Pydantic model serialized to JSON)
        normalized_data         TEXT NOT NULL,

        -- Timestamps
        normalized_at           TEXT NOT NULL,
        created_at              TEXT NOT NULL,
        updated_at              TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_normalized_findings_fingerprint
        ON normalized_findings (fingerprint)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_normalized_findings_status
        ON normalized_findings (normalization_status)
    """,

    # ── Stage 2: Multi-View Extraction ────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS finding_views (
        id              TEXT PRIMARY KEY,       -- UUID
        finding_id      TEXT NOT NULL REFERENCES normalized_findings(finding_id),
        view_type       TEXT NOT NULL,
            -- description | location | reproduction | impact

        -- Extracted content
        view_text       TEXT,                   -- Redacted embedding-ready text (null if missing)
        view_structured TEXT NOT NULL DEFAULT '{}', -- JSON dict of structured sub-fields

        -- Quality metadata
        view_status         TEXT NOT NULL,
            -- available | partial | inferred | missing | conflicting
        confidence          REAL NOT NULL DEFAULT 0.0,  -- 0.0–1.0
        extraction_method   TEXT NOT NULL DEFAULT 'structured_fields',
            -- structured_fields | structured_fields_and_rules | regex_extraction
            -- | keyword_inference | llm_assisted | missing
        source_fields       TEXT NOT NULL DEFAULT '[]', -- JSON array of field names used

        warnings        TEXT NOT NULL DEFAULT '[]',     -- JSON array of warning strings

        -- Timestamps
        extracted_at    TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,

        UNIQUE (finding_id, view_type)  -- one row per view type per finding
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_finding_views_finding
        ON finding_views (finding_id)
    """,

    # ── Stage 3: Embeddings ───────────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS finding_embeddings (
        id                  TEXT PRIMARY KEY,   -- UUID
        finding_id          TEXT NOT NULL REFERENCES normalized_findings(finding_id),
        view_type           TEXT NOT NULL,
            -- description | location | reproduction | impact | combined

        -- Vector data
        embedding_vector    TEXT,               -- JSON float array, null if view missing
        model_name          TEXT NOT NULL,
        model_version       TEXT,
        embedding_dimension INTEGER NOT NULL,
        input_text_hash     TEXT,               -- SHA-256 of text that was embedded

        -- Timestamps
        generated_at        TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL,

        UNIQUE (finding_id, view_type)
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_finding_embeddings_finding
        ON finding_embeddings (finding_id)
    """,

    # ── Stage 4: Deduplication ────────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS clusters (
        cluster_id          TEXT PRIMARY KEY,   -- UUID
        cluster_method      TEXT NOT NULL,
            -- fingerprint | semantic | manual
        status              TEXT NOT NULL DEFAULT 'candidate',
            -- candidate | merged | kept_separate | rejected_merge | uncertain

        -- Cluster quality
        similarity_score    REAL,               -- weighted cosine similarity (0–1)
        merge_reason        TEXT NOT NULL DEFAULT '[]',  -- JSON array of reason strings
        merge_confidence    REAL,

        -- HDBSCAN run metadata (reproducibility)
        hdbscan_params      TEXT,               -- JSON: {min_cluster_size, min_samples, metric}
        run_at              TEXT NOT NULL,

        -- Timestamps
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,

    """
    CREATE TABLE IF NOT EXISTS cluster_members (
        id          TEXT PRIMARY KEY,           -- UUID
        cluster_id  TEXT NOT NULL REFERENCES clusters(cluster_id),
        finding_id  TEXT NOT NULL REFERENCES normalized_findings(finding_id),
        role        TEXT NOT NULL DEFAULT 'secondary',  -- primary | secondary
        joined_at   TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,

        UNIQUE (cluster_id, finding_id)
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_cluster_members_cluster
        ON cluster_members (cluster_id)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_cluster_members_finding
        ON cluster_members (finding_id)
    """,

    """
    CREATE TABLE IF NOT EXISTS canonical_issues (
        canonical_issue_id  TEXT PRIMARY KEY,   -- UUID
        title               TEXT NOT NULL,
        cluster_id          TEXT REFERENCES clusters(cluster_id),  -- nullable (singleton issues)

        -- Source references
        source_finding_ids  TEXT NOT NULL DEFAULT '[]',  -- JSON array of finding_id strings
        source_scanners     TEXT NOT NULL DEFAULT '[]',  -- JSON array of scanner names

        -- Merge provenance
        merge_method        TEXT NOT NULL,
            -- fingerprint | semantic | manual
        merge_confidence    REAL,
        merge_reason        TEXT NOT NULL DEFAULT '[]',  -- JSON array

        -- Status
        review_status       TEXT NOT NULL DEFAULT 'pending',
            -- pending | merged | kept_separate | rejected_merge

        -- Timestamps
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,

    # ── Stage 5: Sandbox Validation ───────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS validation_runs (
        validation_id       TEXT PRIMARY KEY,   -- UUID
        canonical_issue_id  TEXT NOT NULL REFERENCES canonical_issues(canonical_issue_id),
        finding_id          TEXT NOT NULL REFERENCES normalized_findings(finding_id),

        -- Execution result
        status              TEXT NOT NULL,
            -- confirmed_exploitable | not_exploitable | inconclusive | not_attempted
        confidence          REAL,               -- 0.0–1.0
        sandbox_mode        TEXT NOT NULL,
            -- lab_simulator | docker | skipped
        execution_summary   TEXT,

        -- Timing
        executed_at         TEXT,
        timeout_seconds     INTEGER,

        -- Timestamps
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_validation_runs_issue
        ON validation_runs (canonical_issue_id)
    """,

    # ── Stage 6: Evidence Capture ─────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS artifacts (
        artifact_id     TEXT PRIMARY KEY,       -- UUID

        -- What this artifact belongs to
        entity_type     TEXT NOT NULL,          -- finding | validation | case
        entity_id       TEXT NOT NULL,          -- FK to the appropriate table

        -- Artifact classification
        artifact_type   TEXT NOT NULL,
            -- scanner_record | http_request | http_response | poc_script
            -- container_log | execution_log | validation_summary | threat_intel_response

        -- Content (immutable — never overwrite)
        content         TEXT,                   -- Inline for <10KB, null if file-referenced
        content_hash    TEXT NOT NULL,          -- SHA-256 for integrity verification
        content_size    INTEGER,                -- bytes

        -- Safety
        redacted        INTEGER NOT NULL DEFAULT 0,  -- 1 if secrets have been redacted for display

        -- Extra context
        metadata        TEXT NOT NULL DEFAULT '{}',  -- JSON: status_code, content_type, etc.

        -- Timestamps
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_artifacts_entity
        ON artifacts (entity_type, entity_id)
    """,

    # ── Stage 7: Threat Intelligence ──────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS threat_intelligence (
        -- CVE ID is the natural key; no surrogate UUID needed
        cve_id          TEXT PRIMARY KEY,       -- e.g. CVE-2021-44228

        -- KEV data
        kev_flag        INTEGER NOT NULL DEFAULT 0,  -- 1 if in CISA KEV catalog
        kev_date_added  TEXT,                   -- ISO 8601 date string

        -- EPSS data
        epss_score      REAL,                   -- 0.0–1.0
        epss_percentile REAL,                   -- 0.0–1.0

        -- Cache metadata
        data_source     TEXT NOT NULL DEFAULT 'mock',  -- mock | live
        fetched_at      TEXT NOT NULL,

        -- Standard timestamps
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )
    """,

    # ── Stage 8: Risk Scoring ─────────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS priorities (
        priority_id         TEXT PRIMARY KEY,   -- UUID
        canonical_issue_id  TEXT NOT NULL UNIQUE REFERENCES canonical_issues(canonical_issue_id),
            -- UNIQUE: exactly one priority record per canonical issue

        -- Score output
        risk_score          REAL NOT NULL,      -- 0.0–100.0
        remediation_tier    TEXT NOT NULL,
            -- Immediate | Accelerated | Standard

        -- Full transparency: store every input and weight used
        factors             TEXT NOT NULL DEFAULT '{}', -- JSON: all input values
        weights_used        TEXT NOT NULL DEFAULT '{}', -- JSON: weight values at calc time
        explanation         TEXT NOT NULL DEFAULT '[]', -- JSON array of reason strings

        -- Versioning (so we can recalculate if model changes)
        calculation_version TEXT NOT NULL DEFAULT 'risk-model-1.0',

        -- Timestamps
        calculated_at       TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_priorities_tier
        ON priorities (remediation_tier)
    """,

    # ── Stage 9: Case Generation ──────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS cases (
        case_id             TEXT PRIMARY KEY,   -- UUID
        canonical_issue_id  TEXT NOT NULL UNIQUE REFERENCES canonical_issues(canonical_issue_id),

        -- Status (state machine)
        status              TEXT NOT NULL DEFAULT 'pending_review',
            -- pending_review | approved | rejected | more_evidence_requested

        -- Case content
        title               TEXT NOT NULL,
        summary             TEXT,
        case_data           TEXT NOT NULL DEFAULT '{}', -- Full JSON of Case schema

        -- Timestamps
        created_at          TEXT NOT NULL,
        last_updated_at     TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_cases_status
        ON cases (status)
    """,

    # ── Stage 10: Human Review ────────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS reviews (
        review_id       TEXT PRIMARY KEY,   -- UUID
        case_id         TEXT NOT NULL REFERENCES cases(case_id),

        -- Action details
        action          TEXT NOT NULL,
            -- approved | rejected | requested_evidence | priority_override
            -- merge_split | commented
        actor_id        TEXT NOT NULL DEFAULT 'analyst',
        comment         TEXT,
        reason          TEXT,               -- REQUIRED for rejected and priority_override actions
        previous_status TEXT,
        new_status      TEXT,

        -- Timestamps
        reviewed_at     TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_reviews_case
        ON reviews (case_id)
    """,

    # ── Audit Log (cross-entity) ──────────────────────────────────────────────

    """
    CREATE TABLE IF NOT EXISTS audit_events (
        event_id        TEXT PRIMARY KEY,   -- UUID
        entity_type     TEXT NOT NULL,
            -- finding | cluster | canonical_issue | validation | case | review
        entity_id       TEXT NOT NULL,
        action          TEXT NOT NULL,      -- descriptive action name
        actor           TEXT NOT NULL DEFAULT 'system',  -- system | analyst-id
        details         TEXT NOT NULL DEFAULT '{}',      -- JSON: contextual data
        occurred_at     TEXT NOT NULL,      -- ISO 8601 — immutable timestamp

        -- No updated_at — this table is append-only / immutable
        created_at      TEXT NOT NULL
    )
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_audit_events_entity
        ON audit_events (entity_type, entity_id)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_audit_events_occurred
        ON audit_events (occurred_at)
    """,
]


def init_db() -> None:
    """
    Create all tables and indexes if they don't already exist.
    Called once on application startup from main.py lifespan event.
    Safe to call multiple times (CREATE TABLE IF NOT EXISTS is idempotent).
    """
    with get_db() as conn:
        for statement in _TABLES:
            stmt = statement.strip()
            if stmt:
                conn.execute(stmt)
    print(f"[db] Database initialized at {settings.database_path}")


def get_table_names() -> list[str]:
    """Return list of all user-created table names in the database. Used for verification."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    return [row["name"] for row in rows]
