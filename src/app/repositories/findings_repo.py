"""
repositories/findings_repo.py — All database read/write operations for findings.

Architecture rule: NO module talks to SQLite directly except this repository file.
All persistence operations are centralized here.
"""

import json
from datetime import datetime, timezone
from typing import Optional, Any
from src.app.database import get_db
from src.app.schemas.canonical import NormalizedFinding


class FindingsRepository:
    """Central data access layer. All modules use this to read/write the database."""

    def save_scanner_finding(
        self,
        finding_id: str,
        source_scanner: str,
        source_finding_id: Optional[str],
        ingestion_batch_id: str,
        raw_data: dict[str, Any],
        raw_data_hash: str,
        status: str = "received",
    ) -> None:
        """Save unmodified raw scanner finding to scanner_findings table."""
        now_str = datetime.now(timezone.utc).isoformat()
        raw_json = json.dumps(raw_data, default=str)
        with get_db() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO scanner_findings (
                    finding_id, source_scanner, source_finding_id, ingestion_batch_id,
                    raw_data, raw_data_hash, status, ingested_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    source_scanner,
                    source_finding_id,
                    ingestion_batch_id,
                    raw_json,
                    raw_data_hash,
                    status,
                    now_str,
                    now_str,
                    now_str,
                ),
            )

    def save_normalized_finding(self, finding: NormalizedFinding) -> None:
        """Save canonical NormalizedFinding to normalized_findings table."""
        now_str = datetime.now(timezone.utc).isoformat()
        data_json = finding.model_dump_json()
        warnings_json = json.dumps(finding.quality.warnings)
        errors_json = json.dumps(finding.quality.errors)

        with get_db() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO normalized_findings (
                    finding_id, fingerprint, normalization_status, completeness_score,
                    normalization_warnings, normalization_errors, normalized_data,
                    normalized_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    finding.fingerprint,
                    finding.quality.normalization_status,
                    finding.quality.completeness_score,
                    warnings_json,
                    errors_json,
                    data_json,
                    now_str,
                    now_str,
                    now_str,
                ),
            )
            # Also update scanner_findings status
            db.execute(
                "UPDATE scanner_findings SET status = ?, updated_at = ? WHERE finding_id = ?",
                (finding.quality.normalization_status, now_str, finding.finding_id),
            )

    def get_normalized_finding(self, finding_id: str) -> Optional[NormalizedFinding]:
        """Fetch a single canonical NormalizedFinding by ID."""
        with get_db() as db:
            row = db.execute(
                "SELECT normalized_data FROM normalized_findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()

        if not row:
            return None
        return NormalizedFinding.model_validate_json(row["normalized_data"])

    def list_normalized_findings(self, limit: int = 100, offset: int = 0) -> list[NormalizedFinding]:
        """List canonical NormalizedFindings with pagination."""
        with get_db() as db:
            rows = db.execute(
                "SELECT normalized_data FROM normalized_findings ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

        return [NormalizedFinding.model_validate_json(r["normalized_data"]) for r in rows]

    def count_normalized_findings(self) -> int:
        """Return total count of normalized findings."""
        with get_db() as db:
            row = db.execute("SELECT COUNT(*) as cnt FROM normalized_findings").fetchone()
        return row["cnt"] if row else 0


repo = FindingsRepository()
