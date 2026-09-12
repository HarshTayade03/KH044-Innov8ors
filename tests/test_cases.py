import json
import pytest
from datetime import datetime, timezone

from src.app.database import get_db
from src.app.schemas.case import ReviewDecision, ReviewAction
from src.app.services.case_service import case_service
from src.app.repositories.case_repo import case_repo


def test_case_assembly_and_review_is_audited(finding_factory):
    finding = finding_factory()
    now = datetime.now(timezone.utc).isoformat()
    issue_id = "issue-case-test"
    with get_db() as db:
        db.execute("""INSERT INTO canonical_issues
            (canonical_issue_id,title,cluster_id,source_finding_ids,source_scanners,merge_method,
             merge_confidence,merge_reason,review_status,created_at,updated_at,active)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
                   (issue_id, "SQL injection", None, json.dumps([finding.finding_id]),
                    json.dumps(["burp"]), "fingerprint", 1.0, "[]", "pending", now, now))

    case = case_service.assemble(issue_id)
    assert case.status.value == "pending_review"
    assert case.case_data["source_finding_ids"] == [finding.finding_id]
    reviewed = case_service.review(case.case_id, ReviewAction.APPROVE,
                                    ReviewDecision(actor="analyst-1", reason="Verified evidence"))
    assert reviewed.status.value == "approved"
    assert len(__import__("src.app.repositories.case_repo", fromlist=["case_repo"]).case_repo.audits(case.case_id)) == 1


def test_stale_case_refresh_preserves_retrievable_case_identity(finding_factory):
    first = finding_factory(name="Initial SQL injection")
    now = datetime.now(timezone.utc).isoformat()
    issue_id = "issue-case-refresh"
    with get_db() as db:
        db.execute("""INSERT INTO canonical_issues
            (canonical_issue_id,title,cluster_id,source_finding_ids,source_scanners,merge_method,
             merge_confidence,merge_reason,review_status,created_at,updated_at,active)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
                   (issue_id, "SQL injection", None, json.dumps([first.finding_id]),
                    json.dumps(["burp"]), "fingerprint", 1.0, "[]", "pending", now, now))

    original = case_service.assemble(issue_id)
    second = finding_factory(name="Second SQL injection")
    with get_db() as db:
        db.execute("UPDATE canonical_issues SET source_finding_ids=?, updated_at=? WHERE canonical_issue_id=?",
                   (json.dumps([first.finding_id, second.finding_id]), now, issue_id))

    with pytest.raises(ValueError, match="case is stale"):
        case_service.assemble(issue_id)

    refreshed = case_service.assemble(issue_id)
    assert refreshed.case_id == original.case_id
    assert refreshed.stale is False
    assert __import__("src.app.repositories.case_repo", fromlist=["case_repo"]).case_repo.get(original.case_id) == refreshed


def test_priority_override_preserves_review_state_and_is_inspectable(finding_factory):
    finding = finding_factory()
    now = datetime.now(timezone.utc).isoformat()
    issue_id = "issue-case-override"
    with get_db() as db:
        db.execute("""INSERT INTO canonical_issues
            (canonical_issue_id,title,cluster_id,source_finding_ids,source_scanners,merge_method,
             merge_confidence,merge_reason,review_status,created_at,updated_at,active)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
                   (issue_id, "SQL injection", None, json.dumps([finding.finding_id]),
                    json.dumps(["burp"]), "fingerprint", 1.0, "[]", "pending", now, now))

    case = case_service.assemble(issue_id)
    reviewed = case_service.review(
        case.case_id,
        ReviewAction.PRIORITY_OVERRIDE,
        ReviewDecision(actor_id="analyst-2", reason="Adjusted score after analyst review"),
    )
    assert reviewed.status.value == "pending_review"
    assert case_repo.reviews(case.case_id)[0].action == ReviewAction.PRIORITY_OVERRIDE
    assert case_repo.audits(case.case_id)[0].actor == "analyst-2"


def test_resolve_retires_issue_but_preserves_case_and_audit(finding_factory):
    finding = finding_factory()
    now = datetime.now(timezone.utc).isoformat()
    issue_id = "issue-case-resolve"
    with get_db() as db:
        db.execute("""INSERT INTO canonical_issues
            (canonical_issue_id,title,cluster_id,source_finding_ids,source_scanners,merge_method,
             merge_confidence,merge_reason,review_status,created_at,updated_at,active)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
                   (issue_id, "Resolved SQL injection", None, json.dumps([finding.finding_id]),
                    json.dumps(["burp"]), "fingerprint", 1.0, "[]", "pending", now, now))

    case = case_service.assemble(issue_id)
    resolved = case_service.review(
        case.case_id,
        ReviewAction.RESOLVE,
        ReviewDecision(actor_id="analyst-resolver", reason="Patch deployed and verified"),
    )
    assert resolved.status.value == "resolved"
    with get_db() as db:
        row = db.execute(
            "SELECT active, review_status FROM canonical_issues WHERE canonical_issue_id=?",
            (issue_id,),
        ).fetchone()
    assert row["active"] == 0
    assert row["review_status"] == "resolved"
    assert case_repo.audits(case.case_id)[0].action == "resolved"
