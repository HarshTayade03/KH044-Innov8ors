"""Read-only persistence queries used by the analyst dashboard."""

import json
from src.app.database import get_db


class DashboardRepository:
    def metrics(self) -> dict:
        with get_db() as db:
            counts = {}
            for key, table, where in (
                ("findings", "normalized_findings", ""),
                ("active_issues", "canonical_issues", " WHERE active=1"),
                ("clusters", "clusters", ""),
                ("prioritized_issues", "priorities", ""),
                ("cases", "cases", ""),
                ("validations", "validation_runs", ""),
                ("evidence_artifacts", "artifacts", ""),
            ):
                counts[key] = db.execute(f"SELECT COUNT(*) AS n FROM {table}{where}").fetchone()["n"]
            statuses = db.execute(
                "SELECT status, COUNT(*) AS n FROM cases GROUP BY status ORDER BY status"
            ).fetchall()
        counts["cases_by_status"] = {row["status"]: row["n"] for row in statuses}
        return counts

    def list_cases(self, limit: int, offset: int, status: str | None = None) -> tuple[list[dict], int]:
        where = "WHERE c.status=?" if status else ""
        args: tuple = (status,) if status else ()
        with get_db() as db:
            total = db.execute(f"SELECT COUNT(*) AS n FROM cases c {where}", args).fetchone()["n"]
            rows = db.execute(
                f"""SELECT c.*, i.title AS issue_title, i.active AS issue_active,
                           p.risk_score, p.remediation_tier
                    FROM cases c
                    LEFT JOIN canonical_issues i ON i.canonical_issue_id=c.canonical_issue_id
                    LEFT JOIN priorities p ON p.canonical_issue_id=c.canonical_issue_id
                    {where} ORDER BY COALESCE(p.risk_score, -1) DESC, c.last_updated_at DESC
                    LIMIT ? OFFSET ?""",
                args + (limit, offset),
            ).fetchall()
        return [self._case_row(row) for row in rows], total

    def get_case(self, case_id: str) -> dict | None:
        with get_db() as db:
            row = db.execute(
                """SELECT c.*, i.title AS issue_title, i.active AS issue_active,
                          i.cluster_id, i.source_finding_ids, i.source_scanners,
                          i.merge_method, i.merge_confidence, i.merge_reason,
                          p.risk_score, p.remediation_tier, p.factors, p.explanation,
                          p.calculated_at
                   FROM cases c
                   LEFT JOIN canonical_issues i ON i.canonical_issue_id=c.canonical_issue_id
                   LEFT JOIN priorities p ON p.canonical_issue_id=c.canonical_issue_id
                   WHERE c.case_id=?""",
                (case_id,),
            ).fetchone()
            if not row:
                return None
            result = self._case_row(row)
            result["priority"] = (
                {
                    "risk_score": row["risk_score"],
                    "remediation_tier": row["remediation_tier"],
                    "factors": json.loads(row["factors"] or "{}"),
                    "explanation": json.loads(row["explanation"] or "[]"),
                    "calculated_at": row["calculated_at"],
                }
                if row["risk_score"] is not None else None
            )
            finding_ids = json.loads(row["source_finding_ids"] or "[]")
            result["findings"] = []
            for finding_id in finding_ids:
                finding = db.execute(
                    "SELECT normalized_data FROM normalized_findings WHERE finding_id=?", (finding_id,)
                ).fetchone()
                views = db.execute(
                    "SELECT view_type, view_text, view_structured, view_status, confidence, "
                    "extraction_method, source_fields, warnings FROM finding_views WHERE finding_id=? "
                    "ORDER BY view_type", (finding_id,)
                ).fetchall()
                if finding:
                    data = json.loads(finding["normalized_data"])
                    data["views"] = [self._view_row(view) for view in views]
                    result["findings"].append(data)
            result["cluster"] = self._cluster(db, row["cluster_id"]) if row["cluster_id"] else None
            result["validations"] = self._validations(db, row["canonical_issue_id"])
            result["latest_validation"] = result["validations"][0] if result["validations"] else None
            result["audit"] = self._audit(db, "case", case_id)
            result["simulation_labels"] = [
                "Any lab_simulator validation is simulated and does not prove exploitability.",
                "Threat intelligence is mock-feed data when its source is mock.",
            ]
        return result

    def validations(self, case_id: str) -> list[dict] | None:
        case = self.get_case(case_id)
        return None if case is None else case["validations"]

    def evidence(self, case_id: str) -> list[dict] | None:
        case = self.get_case(case_id)
        if case is None:
            return None
        with get_db() as db:
            values = []
            for validation in case["validations"]:
                values.extend(self._artifacts(db, validation["validation_id"]))
            values.extend(self._artifacts(db, case_id, entity_type="case"))
        return values

    def cluster(self, cluster_id: str) -> dict | None:
        with get_db() as db:
            return self._cluster(db, cluster_id)

    def audit(self, case_id: str) -> list[dict] | None:
        with get_db() as db:
            exists = db.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone()
            return None if not exists else self._audit(db, "case", case_id)

    @staticmethod
    def _case_row(row) -> dict:
        case_data = json.loads(row["case_data"] or "{}")
        result = {
            "case_id": row["case_id"], "canonical_issue_id": row["canonical_issue_id"],
            "status": row["status"], "stale": bool(row["stale"]) if "stale" in row.keys() else False,
            "title": row["title"], "summary": row["summary"],
            "created_at": row["created_at"], "last_updated_at": row["last_updated_at"],
            "case_data": case_data, "issue_title": row["issue_title"] if "issue_title" in row.keys() else None,
            "issue_active": bool(row["issue_active"]) if "issue_active" in row.keys() and row["issue_active"] is not None else None,
            "risk_score": row["risk_score"] if "risk_score" in row.keys() else None,
            "remediation_tier": row["remediation_tier"] if "remediation_tier" in row.keys() else None,
        }
        return result

    @staticmethod
    def _view_row(row) -> dict:
        return {
            "view_type": row["view_type"], "text": row["view_text"],
            "structured": json.loads(row["view_structured"] or "{}"),
            "status": row["view_status"], "confidence": row["confidence"],
            "extraction_method": row["extraction_method"],
            "source_fields": json.loads(row["source_fields"] or "[]"),
            "warnings": json.loads(row["warnings"] or "[]"),
        }

    def _validations(self, db, issue_id: str) -> list[dict]:
        rows = db.execute(
            "SELECT * FROM validation_runs WHERE canonical_issue_id=? ORDER BY created_at DESC", (issue_id,)
        ).fetchall()
        return [
            {
                "validation_id": r["validation_id"], "status": r["status"], "confidence": r["confidence"],
                "sandbox_mode": r["sandbox_mode"], "scenario": r["scenario"], "target_host": r["target_host"],
                "execution_summary": r["execution_summary"], "limitations": json.loads(r["limitations"] or "[]"),
                "executed_at": r["executed_at"], "artifact_ids": [a["artifact_id"] for a in db.execute(
                    "SELECT artifact_id FROM artifacts WHERE entity_type='validation' AND entity_id=?",
                    (r["validation_id"],)).fetchall()],
                "simulation": r["sandbox_mode"] == "lab_simulator",
            } for r in rows
        ]

    @staticmethod
    def _artifacts(db, validation_id: str, entity_type: str = "validation") -> list[dict]:
        rows = db.execute(
            "SELECT * FROM artifacts WHERE entity_type=? AND entity_id=? ORDER BY created_at",
            (entity_type, validation_id),
        ).fetchall()
        return [{key: row[key] for key in (
            "artifact_id", "artifact_type", "content", "content_hash", "content_size",
            "redacted", "metadata", "created_at"
        )} | {"entity_type": entity_type, "entity_id": validation_id,
             "validation_id": validation_id if entity_type == "validation" else None,
             "metadata": json.loads(row["metadata"] or "{}"),
             "redacted": bool(row["redacted"])} for row in rows]

    @staticmethod
    def _cluster(db, cluster_id: str) -> dict | None:
        row = db.execute("SELECT * FROM clusters WHERE cluster_id=?", (cluster_id,)).fetchone()
        if not row:
            return None
        members = db.execute(
            "SELECT cm.finding_id, cm.role, nf.normalized_data FROM cluster_members cm "
            "LEFT JOIN normalized_findings nf ON nf.finding_id=cm.finding_id WHERE cm.cluster_id=?",
            (cluster_id,),
        ).fetchall()
        return {
            "cluster_id": row["cluster_id"], "cluster_method": row["cluster_method"],
            "status": row["status"], "similarity_score": row["similarity_score"],
            "merge_reason": json.loads(row["merge_reason"] or "[]"),
            "merge_confidence": row["merge_confidence"], "run_at": row["run_at"],
            "members": [{"finding_id": m["finding_id"], "role": m["role"],
                         "finding": json.loads(m["normalized_data"]) if m["normalized_data"] else None}
                        for m in members],
        }

    @staticmethod
    def _audit(db, entity_type: str, entity_id: str) -> list[dict]:
        rows = db.execute(
            "SELECT event_id, entity_type, entity_id, action, actor, details, occurred_at "
            "FROM audit_events WHERE entity_type=? AND entity_id=? ORDER BY occurred_at ASC",
            (entity_type, entity_id),
        ).fetchall()
        return [{**dict(row), "details": json.loads(row["details"] or "{}")} for row in rows]


dashboard_repo = DashboardRepository()
