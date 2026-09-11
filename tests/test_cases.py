import json
from datetime import datetime, timezone

from src.app.database import get_db
from src.app.schemas.case import ReviewDecision, ReviewAction
from src.app.services.case_service import case_service


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
