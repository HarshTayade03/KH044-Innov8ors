"""Synthetic demo catalog and loading API checks."""
from fastapi.testclient import TestClient
from src.app.main import app

def test_fixed_dataset_catalog_and_load():
    client = TestClient(app)
    catalog = client.get('/api/v1/demo/datasets')
    assert catalog.status_code == 200
    assert catalog.json()['total_findings'] == 110
    assert len(catalog.json()['datasets']) == 6
    loaded = client.post('/api/v1/demo/datasets/burp-ssrf/load')
    assert loaded.status_code == 200
    assert loaded.json()['total_received'] == 10
    assert client.post('/api/v1/demo/datasets/../../secrets/load').status_code == 404
    metrics = client.get('/api/v1/dashboard/metrics').json()
    assert metrics['findings'] == 10
    assert metrics['active_issues'] == 0
    assert metrics['clusters'] == 0
    assert metrics['prioritized'] == 0
    assert metrics['validations'] == 0
    assert metrics['evidence_artifacts'] == 0
    assert metrics['provenance']['validation_mode'] == 'offline_lab_simulator'
