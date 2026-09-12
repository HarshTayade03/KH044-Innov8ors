"""Case assembly and transactional human review service."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from src.app.repositories.case_repo import case_repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.risk_repo import risk_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.case import (
    AuditEvent,
    Case,
    CaseDetail,
    CaseStatus,
    ReviewAction,
    ReviewActionType,
    ReviewRecord,
)
from src.app.schemas.risk import RemediationTier


class CaseConflict(ValueError):
    pass


class CaseService:
    def generate(self, issue_id: str) -> Case:
        issue = dedup_repo.get_canonical_issue(issue_id)
        if not issue or not issue.active:
            raise LookupError(f"Canonical issue '{issue_id}' not found.")
        current = case_repo.get_for_issue(issue_id)
        if current and not current.stale and current.status == CaseStatus.PENDING_REVIEW:
            return current

        findings = [findings_repo.get_normalized_finding(fid) for fid in issue.source_finding_ids]
        findings = [finding for finding in findings if finding]
        if not findings:
            raise LookupError(f"No source findings found for canonical issue '{issue_id}'.")
        priority = risk_repo.get_priority_by_issue(issue_id)
        validation = validation_repo.latest_for_issue(issue_id)
        artifact_data = validation_repo.list_artifacts(validation.validation_id) if validation else []
        assembled = {
            "provenance": {"reported": "scanner fixtures", "derived": "platform normalization and views",
                            "simulated": bool(validation), "reviewed": False},
            "issue": issue.model_dump(mode="json"),
            "findings": [],
            "priority": priority.model_dump(mode="json") if priority else None,
            "validation": validation.model_dump(mode="json") if validation else None,
            "artifacts": [artifact.model_dump(mode="json") for artifact in artifact_data],
        }
        for finding in findings:
            views = findings_repo.get_finding_views(finding.finding_id)
            embeddings = findings_repo.get_finding_embeddings(finding.finding_id)
            assembled["findings"].append({
                "finding": finding.model_dump(mode="json"),
                "views": views.model_dump(mode="json") if views else None,
                "embedding_provenance": {
                    "backend": embeddings.embedding_model,
                    "version": embeddings.model_version,
                    "dimension": embeddings.embedding_dimension,
                    "missing_views": embeddings.missing_views,
                } if embeddings else None,
            })
        now = datetime.now(timezone.utc)
        case = Case(
            case_id=current.case_id if current else f"case-{uuid.uuid4()}",
            canonical_issue_id=issue_id,
            status=CaseStatus.PENDING_REVIEW,
            title=issue.title,
            summary=f"Reviewable case assembled from {len(findings)} source finding(s).",
            case_data=assembled,
            stale=False,
            created_at=current.created_at if current else now,
            last_updated_at=now,
            updated_at=now,
        )
        case_repo.save(case)
        case_repo.audit(AuditEvent(
            event_id=str(uuid.uuid4()), entity_type="case", entity_id=case.case_id,
            action="assembled" if not current else "rebuilt", actor="system",
            details={"canonical_issue_id": issue_id, "source_count": len(findings)}, occurred_at=now,
        ))
        return case

    def list_cases(self, limit: int = 100, offset: int = 0, status: Optional[CaseStatus] = None) -> list[Case]:
        return case_repo.list(limit, offset, status)

    def detail(self, case_id: str) -> CaseDetail:
        case = case_repo.detail(case_id)
        if not case:
            raise LookupError(f"Case '{case_id}' not found.")
        return case

    def review(self, case_id: str, action_type: ReviewActionType, action: ReviewAction) -> CaseDetail:
        case = case_repo.get(case_id)
        if not case:
            raise LookupError(f"Case '{case_id}' not found.")
        if case.stale:
            raise CaseConflict("Case is stale; regenerate it before review.")
        if case.status in {CaseStatus.APPROVED, CaseStatus.REJECTED}:
            raise CaseConflict(f"Case already has terminal status '{case.status.value}'.")
        new_status = {
            ReviewActionType.APPROVED: CaseStatus.APPROVED,
            ReviewActionType.REJECTED: CaseStatus.REJECTED,
            ReviewActionType.REQUESTED_EVIDENCE: CaseStatus.MORE_EVIDENCE_REQUESTED,
            ReviewActionType.PRIORITY_OVERRIDE: case.status,
        }[action_type]
        if action_type == ReviewActionType.PRIORITY_OVERRIDE and not action.new_tier:
            raise ValueError("new_tier is required for priority overrides")
        if action_type == ReviewActionType.PRIORITY_OVERRIDE:
            try:
                new_tier = RemediationTier(action.new_tier).value
            except ValueError as exc:
                raise ValueError("new_tier must be Immediate, Accelerated or Standard") from exc
        else:
            new_tier = None
        now = datetime.now(timezone.utc)
        case_data = dict(case.case_data)
        if new_tier:
            priority = dict(case_data.get("priority") or {})
            priority["remediation_tier"] = new_tier
            priority["override"] = {"actor_id": action.actor_id, "reason": action.reason}
            case_data["priority"] = priority
        updated = case.model_copy(update={"status": new_status, "case_data": case_data, "last_updated_at": now, "updated_at": now})
        review = ReviewRecord(
            review_id=f"review-{uuid.uuid4()}", case_id=case_id, action=action_type,
            actor_id=action.actor_id, comment=action.comment, reason=action.reason,
            previous_status=case.status, new_status=new_status, reviewed_at=now,
        )
        audit = AuditEvent(
            event_id=str(uuid.uuid4()), entity_type="case", entity_id=case_id,
            action=action_type.value, actor=action.actor_id,
            details={"reason": action.reason, "comment": action.comment, "new_tier": new_tier,
                     "previous_status": case.status.value, "new_status": new_status.value}, occurred_at=now,
        )
        try:
            case_repo.update_review(updated, review, audit)
        except ValueError as exc:
            raise CaseConflict(str(exc)) from exc
        return self.detail(case_id)


case_service = CaseService()