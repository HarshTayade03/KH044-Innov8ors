"""Acceptance checks for truthful dashboard aggregates."""

from fastapi.testclient import TestClient

from src.app.main import app
from src.app.services.deduplicator import deduplicator_service


def test_dashboard_metrics_are_implemented_and_provenance_labeled(finding_factory):
    finding_factory(name="Dashboard SQLi", cwe_ids=["CWE-89"])
    deduplicator_service.run_deduplication()

    response = TestClient(app).get("/api/v1/dashboard/metrics")

    assert response.status_code == 200
    body = response.json()
    assert body["findings"] == 1
    assert body["active_issues"] == 1
    assert body["clusters"] == 0
    assert body["prioritized"] == 0
    assert body["provenance"] == {
        "validation_mode": "offline_lab_simulator",
        "threat_intelligence": "mock",
        "real_exploitability_confirmed": False,
    }
