"""Acceptance tests for case assembly and human review."""

from fastapi.testclient import TestClient

from src.app.main import app
from src.app.repositories.case_repo import case_repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.database import get_db
from src.app.services.case_service import case_service
from src.app.services.deduplicator import deduplicator_service


def make_case(finding_factory):
    finding = finding_factory()
    deduplicator_service.run_deduplication()
    issue = next(i for i in dedup_repo.list_canonical_issues() if finding.finding_id in i.source_finding_ids)
    return case_service.generate(issue.canonical_issue_id)


def test_case_assembly_is_idempotent_and_contains_provenance(finding_factory):
    case = make_case(finding_factory)
    again = case_service.generate(case.canonical_issue_id)
    assert again.case_id == case.case_id
    assert case.case_data["provenance"]["reported"] == "scanner fixtures"
    assert case.case_data["findings"][0]["finding"]["finding_id"]
    assert case_repo.detail(case.case_id).audit_events


def test_review_requires_reason_and_records_audit(finding_factory):
    case = make_case(finding_factory)
    client = TestClient(app)
    missing = client.post(f"/api/v1/cases/{case.case_id}/reject", json={"actor_id": "analyst", "reason": "  "})
    assert missing.status_code == 422
    response = client.post(f"/api/v1/cases/{case.case_id}/reject", json={"actor_id": "analyst-1", "reason": "Not reproducible in scope"})
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    repeated = client.post(f"/api/v1/cases/{case.case_id}/reject", json={"actor_id": "analyst-2", "reason": "repeat"})
    assert repeated.status_code == 409
    detail = client.get(f"/api/v1/cases/{case.case_id}").json()
    assert detail["reviews"][0]["actor_id"] == "analyst-1"
    assert detail["audit_events"][-1]["action"] == "rejected"


def test_case_missing_issue_is_404():
    client = TestClient(app)
    assert client.post("/api/v1/canonical-issues/missing/generate-case").status_code == 404


def test_priority_override_updates_case_snapshot(finding_factory):
    case = make_case(finding_factory)
    client = TestClient(app)
    response = client.post(
        f"/api/v1/cases/{case.case_id}/override-priority",
        json={"actor_id": "analyst-1", "reason": "Business impact requires acceleration", "new_tier": "Accelerated"},
    )
    assert response.status_code == 200
    assert response.json()["case_data"]["priority"]["remediation_tier"] == "Accelerated"


def test_stale_case_must_be_rebuilt_before_review(finding_factory):
    case = make_case(finding_factory)
    with get_db() as db:
        db.execute("UPDATE cases SET stale=1 WHERE case_id=?", (case.case_id,))
    client = TestClient(app)
    blocked = client.post(
        f"/api/v1/cases/{case.case_id}/approve",
        json={"actor_id": "analyst-1", "reason": "Review attempted on stale data"},
    )
    assert blocked.status_code == 409
    rebuilt = client.post(f"/api/v1/canonical-issues/{case.canonical_issue_id}/generate-case")
    assert rebuilt.status_code == 201
    assert rebuilt.json()["case_id"] == case.case_id
    assert rebuilt.json()["stale"] is False


def test_case_queue_and_detail_contract(finding_factory):
    case = make_case(finding_factory)
    client = TestClient(app)
    queue = client.get("/api/v1/cases", params={"status": "pending_review"})
    assert queue.status_code == 200
    assert queue.json()["cases"][0]["case_id"] == case.case_id
    detail = client.get(f"/api/v1/cases/{case.case_id}")
    assert detail.status_code == 200
    assert {"reviews", "audit_events"}.issubset(detail.json())