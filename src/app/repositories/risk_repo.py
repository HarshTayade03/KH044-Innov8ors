"""
repositories/risk_repo.py — Database repository for priority scoring records.
"""

import json
from datetime import datetime, timezone
from typing import Optional
from src.app.database import get_db
from src.app.schemas.risk import PriorityResult, RemediationTier


class RiskRepository:
    """Repository for reading and writing priority score results."""

    def save_priority(self, result: PriorityResult) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        with get_db() as db:
            if not db.execute("SELECT 1 FROM canonical_issues WHERE canonical_issue_id=? AND active=1", (result.canonical_issue_id,)).fetchone():
                raise ValueError("Cannot prioritize a retired or missing canonical issue")
            previous = db.execute("SELECT priority_id FROM priorities WHERE canonical_issue_id=?", (result.canonical_issue_id,)).fetchone()
            if previous:
                result.priority_id = previous["priority_id"]
            db.execute(
                """
                INSERT INTO priorities (
                    priority_id, canonical_issue_id, risk_score, remediation_tier,
                    factors, weights_used, explanation, calculation_version,
                    calculated_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(canonical_issue_id) DO UPDATE SET
                    risk_score=excluded.risk_score,
                    remediation_tier=excluded.remediation_tier,
                    factors=excluded.factors,
                    weights_used=excluded.weights_used,
                    explanation=excluded.explanation,
                    calculation_version=excluded.calculation_version,
                    calculated_at=excluded.calculated_at,
                    updated_at=excluded.updated_at
                """,
                (
                    result.priority_id,
                    result.canonical_issue_id,
                    result.risk_score,
                    result.remediation_tier.value,
                    json.dumps(result.factors, default=str),
                    json.dumps(result.weights_used),
                    json.dumps(result.explanation),
                    result.calculation_version,
                    result.calculated_at.isoformat(),
                    now_str,
                    now_str,
                )
            )

    def get_priority_by_issue(self, canonical_issue_id: str) -> Optional[PriorityResult]:
        with get_db() as db:
            row = db.execute(
                "SELECT p.* FROM priorities p JOIN canonical_issues c USING (canonical_issue_id) WHERE c.active=1 AND p.canonical_issue_id = ?",
                (canonical_issue_id,)
            ).fetchone()

        if not row:
            return None

        return PriorityResult(
            priority_id=row["priority_id"],
            canonical_issue_id=row["canonical_issue_id"],
            risk_score=row["risk_score"],
            remediation_tier=RemediationTier(row["remediation_tier"]),
            factors=json.loads(row["factors"]),
            weights_used=json.loads(row["weights_used"]),
            explanation=json.loads(row["explanation"]),
            calculation_version=row["calculation_version"],
            calculated_at=datetime.fromisoformat(row["calculated_at"]),
        )

    def list_priorities(self, limit: int = 100, offset: int = 0) -> list[PriorityResult]:
        with get_db() as db:
            rows = db.execute(
                "SELECT p.canonical_issue_id FROM priorities p JOIN canonical_issues c USING (canonical_issue_id) WHERE c.active=1 ORDER BY p.risk_score DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()

        results = []
        for r in rows:
            p = self.get_priority_by_issue(r["canonical_issue_id"])
            if p:
                results.append(p)
        return results


risk_repo = RiskRepository()
