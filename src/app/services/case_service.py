"""Case assembly and transactional analyst review service."""
import uuid
from datetime import datetime, timezone
from src.app.database import get_db, transaction
from src.app.repositories.case_repo import case_repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.risk_repo import risk_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.case import Case, CaseStatus, Review, ReviewAction, ReviewDecision, AuditEvent

class CaseService:
    def assemble(self, issue_id):
        issue = dedup_repo.get_canonical_issue(issue_id)
        if not issue or not issue.active:
            raise LookupError("Canonical issue is missing or retired")
        existing = case_repo.get_for_issue(issue_id)
        membership = sorted(issue.source_finding_ids)
        if existing and not existing.stale:
            if sorted(existing.case_data.get("source_finding_ids", [])) != membership:
                existing.stale = True
                with transaction() as db:
                    db.execute("UPDATE cases SET stale=1,last_updated_at=?,updated_at=? WHERE case_id=?",
                               (datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(), existing.case_id))
                raise ValueError("Existing case is stale because issue membership changed")
            if existing.status != CaseStatus.PENDING_REVIEW:
                return existing
            return existing
        findings = []
        for fid in membership:
            finding = findings_repo.get_normalized_finding(fid)
            if finding:
                views = findings_repo.get_finding_views(fid)
                findings.append({"finding": finding.model_dump(mode="json"),
                                 "views": views.model_dump(mode="json") if views else None})
        priority = risk_repo.get_priority_by_issue(issue_id)
        validation = validation_repo.latest_for_issue(issue_id)
        evidence = validation_repo.list_artifacts(validation.validation_id) if validation else []
        now = datetime.now(timezone.utc)
        data = {"canonical_issue": issue.model_dump(mode="json"), "source_finding_ids": membership,
                "findings": findings, "priority": priority.model_dump(mode="json") if priority else None,
                "latest_validation": validation.model_dump(mode="json") if validation else None,
                "evidence_references": [a.model_dump(mode="json") for a in evidence]}
        case = Case(case_id=str(uuid.uuid4()), canonical_issue_id=issue_id, status=CaseStatus.PENDING_REVIEW,
                    title=issue.title, summary=None, stale=False, case_data=data, created_at=now, last_updated_at=now)
        case_repo.save(case)
        return case

    def review(self, case_id, action: ReviewAction, decision: ReviewDecision):
        actor, reason = (decision.actor or decision.actor_id or "").strip(), decision.reason.strip()
        if not actor or not reason:
            raise ValueError("actor and reason are required")
        with transaction() as db:
            row = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not row: raise LookupError("Case not found")
            case = case_repo._case(row)
            issue = db.execute("SELECT active FROM canonical_issues WHERE canonical_issue_id=?", (case.canonical_issue_id,)).fetchone()
            if not issue or not issue["active"] or case.stale:
                raise ValueError("Case is stale or canonical issue is retired")
            if action == ReviewAction.APPROVE: new = CaseStatus.APPROVED
            elif action == ReviewAction.REJECT: new = CaseStatus.REJECTED
            else: new = CaseStatus.EVIDENCE_REQUESTED
            if case.status in (CaseStatus.APPROVED, CaseStatus.REJECTED):
                raise RuntimeError("Terminal case decisions cannot be repeated")
            now = datetime.now(timezone.utc)
            db.execute("UPDATE cases SET status=?,last_updated_at=?,updated_at=? WHERE case_id=?",
                       (new.value, now.isoformat(), now.isoformat(), case_id))
            review = Review(review_id=str(uuid.uuid4()),case_id=case_id,action=action,actor_id=actor,reason=reason,
                            previous_status=case.status,new_status=new,reviewed_at=now)
            case_repo.add_review(review, db)
            case_repo.add_audit(AuditEvent(event_id=str(uuid.uuid4()),entity_type="case",entity_id=case_id,
                              action=action.value,actor=actor,details={"reason":reason,"previous_status":case.status.value,"new_status":new.value},occurred_at=now), db)
        return case_repo.get(case_id)

case_service = CaseService()
