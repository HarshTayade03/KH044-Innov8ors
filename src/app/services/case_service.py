"""Case assembly and analyst-only review state transitions."""
import uuid
from datetime import datetime, timezone

from src.app.database import transaction
from src.app.repositories.case_repo import case_repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.risk_repo import risk_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.case import Case, CaseStatus, ReviewAction


class CaseError(Exception):
    pass


class CaseValidationError(CaseError):
    pass


class CaseService:
    def generate(self, issue_id: str) -> Case:
        issue = dedup_repo.get_canonical_issue(issue_id)
        if not issue or not issue.active:
            raise CaseError(f"Active canonical issue '{issue_id}' not found.")
        existing = case_repo.get_for_issue(issue_id)
        if existing and not existing.stale and existing.status == CaseStatus.PENDING_REVIEW:
            return existing
        if existing and existing.stale:
            raise CaseError(f"Case '{existing.case_id}' is stale and requires a new canonical issue.")
        if existing:
            raise CaseError(f"Case '{existing.case_id}' has already been reviewed.")

        findings = [findings_repo.get_normalized_finding(fid) for fid in issue.source_finding_ids]
        findings = [f for f in findings if f is not None]
        views = {f.finding_id: findings_repo.get_finding_views(f.finding_id) for f in findings}
        priority = risk_repo.get_priority_by_issue(issue_id)
        validation = validation_repo.latest_for_issue(issue_id)
        artifacts = validation_repo.list_artifacts(validation.validation_id) if validation else []
        data = {
            "canonical_issue": issue.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in findings],
            "views": {fid: (v.model_dump(mode="json") if v else None) for fid, v in views.items()},
            "priority": priority.model_dump(mode="json") if priority else None,
            "latest_validation": validation.model_dump(mode="json") if validation else None,
            "artifact_refs": [a.model_dump(mode="json", exclude={"content"}) for a in artifacts],
        }
        now = datetime.now(timezone.utc)
        case = Case(case_id=str(uuid.uuid4()), canonical_issue_id=issue_id,
                    title=issue.title, summary=f"Case assembled from {len(findings)} finding(s).",
                    case_data=data, created_at=now, last_updated_at=now)
        case_repo.save_snapshot(case)
        return case

    def get(self, case_id: str) -> Case:
        case = case_repo.get(case_id)
        if not case:
            raise CaseError(f"Case '{case_id}' not found.")
        return case

    def review(self, case_id: str, action: str, request: ReviewAction) -> Case:
        if not request.actor_id.strip() or not request.reason.strip():
            raise CaseValidationError("actor_id and reason are required.")
        with transaction() as db:
            row = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not row:
                raise CaseError(f"Case '{case_id}' not found.")
            current = CaseStatus(row["status"])
            if row["stale"]:
                raise CaseError("Stale cases cannot be reviewed.")
            if current in (CaseStatus.APPROVED, CaseStatus.REJECTED):
                raise CaseError("Terminal case decisions cannot be repeated.")
            new_status = {
                "approved": CaseStatus.APPROVED,
                "rejected": CaseStatus.REJECTED,
                "requested_evidence": CaseStatus.MORE_EVIDENCE_REQUESTED,
                "priority_override": current,
            }.get(action)
            if new_status is None:
                raise CaseError(f"Unsupported review action '{action}'.")
            if action == "priority_override" and request.priority is None:
                raise CaseValidationError("priority is required for a priority override.")
            now = datetime.now(timezone.utc).isoformat()
            if action == "priority_override":
                import json
                data = json.loads(row["case_data"])
                data["priority"] = request.priority
                db.execute("UPDATE cases SET case_data=?, last_updated_at=?, updated_at=? WHERE case_id=?",
                           (json.dumps(data), now, now, case_id))
            else:
                db.execute("UPDATE cases SET status=?, last_updated_at=?, updated_at=? WHERE case_id=?",
                           (new_status.value, now, now, case_id))
            case_repo.create_review(db, case_id, action, request.actor_id.strip(),
                                    request.reason.strip(), current, new_status)
            case_repo.append_audit(db, case_id, action, request.actor_id.strip(),
                                   {"reason": request.reason.strip(), "previous_status": current.value,
                                    "new_status": new_status.value if new_status else None})
        return self.get(case_id)

    def list(self, **kwargs):
        return case_repo.list(**kwargs)


case_service = CaseService()
