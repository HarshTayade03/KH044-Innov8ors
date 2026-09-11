"""Acceptance tests for safe offline validation and evidence."""
import hashlib
import pytest
from fastapi.testclient import TestClient
from src.app.main import app
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.database import get_db
from src.app.schemas.validation import ValidationRequest, ValidationStatus
from src.app.services.deduplicator import deduplicator_service
from src.app.services.risk_engine import risk_engine
from src.app.services.sandbox import sandbox_service

def make_issue(finding_factory, **overrides):
    finding = finding_factory(**overrides)
    deduplicator_service.run_deduplication()
    return next(issue for issue in dedup_repo.list_canonical_issues() if finding.finding_id in issue.source_finding_ids)

@pytest.mark.parametrize(("cwe", "scenario"), [("CWE-89", "sqli"), ("CWE-79", "xss"), ("CWE-918", "ssrf")])
def test_three_scenarios_round_trip_and_hash_integrity(finding_factory, cwe, scenario):
    issue = make_issue(finding_factory, name=scenario, cwe_ids=[cwe], path=f"/{scenario}")
    result = sandbox_service.validate(issue.canonical_issue_id, ValidationRequest(scenario=scenario))
    assert result.status == ValidationStatus.SIMULATED_MATCH
    stored = validation_repo.get(result.validation_id)
    artifact = validation_repo.list_artifacts(result.validation_id)[0]
    assert stored == result
    assert artifact.content_hash == hashlib.sha256(artifact.content.encode()).hexdigest()
    assert artifact.content_size == len(artifact.content.encode())
    assert artifact.metadata["simulation"] is True

def test_timeout_unknown_allowlist_and_docker(finding_factory):
    issue = make_issue(finding_factory)
    assert sandbox_service.validate(issue.canonical_issue_id, ValidationRequest(simulate_timeout=True)).status == ValidationStatus.INCONCLUSIVE
    assert sandbox_service.validate(issue.canonical_issue_id, ValidationRequest(scenario="unknown")).status == ValidationStatus.INCONCLUSIVE
    client = TestClient(app)
    assert client.post(f"/api/v1/canonical-issues/{issue.canonical_issue_id}/validate", json={"target_host": "public.example.com"}).status_code == 422
    assert client.post(f"/api/v1/canonical-issues/{issue.canonical_issue_id}/validate", json={"mode": "docker"}).status_code == 422


def test_inconclusive_validation_has_neutral_risk_factor(finding_factory):
    issue = make_issue(finding_factory)
    sandbox_service.validate(issue.canonical_issue_id, ValidationRequest(simulate_timeout=True))
    priority = risk_engine.calculate_priority(issue.canonical_issue_id)
    assert priority.factors["validation_status"] == "inconclusive"
    assert priority.factors["validation_factor"] == 0.5

def test_evidence_redaction_api_and_risk_integration(finding_factory):
    issue = make_issue(finding_factory, evidence="password=hunter2 Authorization: Bearer secret-token")
    baseline = risk_engine.calculate_priority(issue.canonical_issue_id)
    client = TestClient(app)
    response = client.post(f"/api/v1/canonical-issues/{issue.canonical_issue_id}/validate", json={})
    assert response.status_code == 200
    validation = response.json()
    evidence = client.get(f"/api/v1/validations/{validation['validation_id']}/evidence")
    assert evidence.status_code == 200
    content = evidence.json()["artifacts"][0]["content"]
    assert "hunter2" not in content and "secret-token" not in content
    rescored = risk_engine.calculate_priority(issue.canonical_issue_id)
    assert rescored.factors["validation_status"] == "simulated_match"
    assert rescored.factors["validation_factor"] == 0.75
    assert rescored.risk_score > baseline.risk_score
    assert client.get("/api/v1/validations/missing").status_code == 404

def test_repeated_runs_are_append_only(finding_factory):
    issue = make_issue(finding_factory)
    first = sandbox_service.validate(issue.canonical_issue_id, ValidationRequest())
    second = sandbox_service.validate(issue.canonical_issue_id, ValidationRequest())
    assert first.validation_id != second.validation_id
    assert validation_repo.get(first.validation_id) is not None
    assert validation_repo.get(second.validation_id) is not None

def test_tampered_evidence_is_never_served(finding_factory):
    issue = make_issue(finding_factory)
    result = sandbox_service.validate(issue.canonical_issue_id, ValidationRequest())
    artifact = validation_repo.list_artifacts(result.validation_id)[0]
    with get_db() as db:
        db.execute("UPDATE artifacts SET content=? WHERE artifact_id=?", ("tampered", artifact.artifact_id))
    with pytest.raises(ValueError, match="failed integrity verification"):
        validation_repo.list_artifacts(result.validation_id)
    response = TestClient(app).get(f"/api/v1/validations/{result.validation_id}/evidence")
    assert response.status_code == 500
