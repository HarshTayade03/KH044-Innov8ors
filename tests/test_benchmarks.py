"""Acceptance checks for benchmark provenance and safety metadata."""

from fastapi.testclient import TestClient

from src.app.main import app


def test_benchmark_catalog_is_read_only_and_explicitly_provenanced():
    response = TestClient(app).get("/api/v1/benchmarks")

    assert response.status_code == 200
    body = response.json()
    assert len(body["sources"]) == 6
    assert all(source["execution_allowed"] is False for source in body["sources"])
    assert all(source["authorization_required"] is True for source in body["sources"])
    assert "isolated" in body["safety_policy"]
