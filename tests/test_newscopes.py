"""
tests/test_newscopes.py — Automated tests for Module M8 (AI Patch Remediation, Integrations & Docker Sandbox).
"""

import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from src.app.database import get_db
from src.app.main import app
from src.app.services.patch_generator import PatchGeneratorService
from src.app.services.notifier import IntegrationNotifierService
from src.app.services.docker_sandbox import DockerSandboxService

client = TestClient(app)


def test_ai_patch_generator_service():
    """Verify AI patch generator produces valid unified diff and syntax validation."""
    service = PatchGeneratorService()
    res = service.generate_patch(
        canonical_issue_id="issue-patch-1",
        title="SQL Injection in login query",
        cwe_primary="CWE-89",
        location_view="/app/auth/login.py:L45",
        reproduction_view="admin' OR '1'='1",
        target_language="python",
    )
    assert res.canonical_issue_id == "issue-patch-1"
    assert res.cwe_id == "CWE-89"
    assert "SELECT" in res.vulnerable_code_snippet
    assert "%s" in res.fixed_code_snippet
    assert "--- a/" in res.git_diff
    assert res.validation.is_valid_syntax is True


def test_remediation_patch_api_endpoint(finding_factory):
    """Verify POST /api/v1/canonical-issues/{id}/remediation-patch API route."""
    finding = finding_factory()
    now = datetime.now(timezone.utc).isoformat()
    issue_id = "issue-api-patch-test"

    with get_db() as db:
        db.execute(
            """INSERT INTO canonical_issues
            (canonical_issue_id,title,cluster_id,source_finding_ids,source_scanners,merge_method,
             merge_confidence,merge_reason,review_status,created_at,updated_at,active)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
            (issue_id, "SQL Injection in User Search", None, json.dumps([finding.finding_id]),
             json.dumps(["burp"]), "fingerprint", 1.0, "[]", "pending", now, now),
        )

    response = client.post(f"/api/v1/canonical-issues/{issue_id}/remediation-patch")
    assert response.status_code == 200
    data = response.json()
    assert data["canonical_issue_id"] == issue_id
    assert "git_diff" in data
    assert data["validation"]["is_valid_syntax"] is True


def test_integrations_status_api():
    """Verify GET /api/v1/integrations/status API route."""
    response = client.get("/api/v1/integrations/status")
    assert response.status_code == 200
    data = response.json()
    assert data["inbound_webhook_enabled"] is True
    assert "jira" in data["supported_export_formats"]
    assert "github" in data["supported_export_formats"]


def test_inbound_webhook_ingest_api():
    """Verify POST /api/v1/integrations/webhook/ingest API route."""
    payload = {
        "source_name": "github_actions_sarif",
        "repository": "my-org/my-repo",
        "findings": [
            {
                "ruleId": "CWE-89",
                "message": {"text": "Potential SQL Injection in query"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.py"}}}]
            }
        ]
    }
    response = client.post("/api/v1/integrations/webhook/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "accepted"
    assert data["findings_processed"] == 1
    assert "batch_id" in data


def test_test_outbound_webhook_api():
    """Verify POST /api/v1/integrations/test-webhook endpoint."""
    payload = {
        "target_url": "https://httpbin.org/post",
        "event_type": "test_alert",
        "payload": {"title": "Unit Test Alert", "risk_score": 90.0}
    }
    response = client.post("/api/v1/integrations/test-webhook", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "success" in data
    assert "message" in data


def test_case_ticket_export_api(finding_factory):
    """Verify POST /api/v1/cases/{case_id}/export-ticket endpoint."""
    from src.app.services.case_service import case_service
    finding = finding_factory()
    now = datetime.now(timezone.utc).isoformat()
    issue_id = "issue-export-test"

    with get_db() as db:
        db.execute(
            """INSERT INTO canonical_issues
            (canonical_issue_id,title,cluster_id,source_finding_ids,source_scanners,merge_method,
             merge_confidence,merge_reason,review_status,created_at,updated_at,active)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
            (issue_id, "XSS in Comment Box", None, json.dumps([finding.finding_id]),
             json.dumps(["zap"]), "fingerprint", 1.0, "[]", "pending", now, now),
        )

    case = case_service.assemble(issue_id)

    # Test Jira format
    jira_resp = client.post(f"/api/v1/cases/{case.case_id}/export-ticket?format_type=jira")
    assert jira_resp.status_code == 200
    jira_data = jira_resp.json()
    assert jira_data["format_type"] == "jira"
    assert "h2. Vulnerability Details" in jira_data["ticket_body_markdown"]

    # Test GitHub format
    gh_resp = client.post(f"/api/v1/cases/{case.case_id}/export-ticket?format_type=github")
    assert gh_resp.status_code == 200
    gh_data = gh_resp.json()
    assert gh_data["format_type"] == "github"
    assert "## 🚨 Security Vulnerability Report" in gh_data["ticket_body_markdown"]


def test_docker_sandbox_status_and_execution_api(finding_factory):
    """Verify GET /sandbox/docker/status and POST /sandbox/docker/execute/{id}."""
    status_resp = client.get("/api/v1/sandbox/docker/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert "docker_available" in status_data
    assert "policy_enabled" in status_data

    finding = finding_factory()
    now = datetime.now(timezone.utc).isoformat()
    issue_id = "issue-docker-test"

    with get_db() as db:
        db.execute(
            """INSERT INTO canonical_issues
            (canonical_issue_id,title,cluster_id,source_finding_ids,source_scanners,merge_method,
             merge_confidence,merge_reason,review_status,created_at,updated_at,active)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
            (issue_id, "SSRF Probe Test", None, json.dumps([finding.finding_id]),
             json.dumps(["nessus"]), "fingerprint", 1.0, "[]", "pending", now, now),
        )

    exec_resp = client.post(f"/api/v1/sandbox/docker/execute/{issue_id}")
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["canonical_issue_id"] == issue_id
    assert "sha256_digest" in exec_data
    assert exec_data["execution_status"] in ["completed", "disabled_by_policy", "docker_unavailable", "error"]
