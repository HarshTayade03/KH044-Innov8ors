"""Synthetic demo catalog and loading API checks."""
from fastapi.testclient import TestClient
from src.app.main import app
import json
from concurrent.futures import ThreadPoolExecutor
import pytest
from src.app.database import get_db
from src.app.repositories.findings_repo import repo
from src.app.services.demo import DATASETS, DATA_DIR, load_dataset
from src.app.services.normalizer import normalizer_service
from src.app.parsers.base import resolve_cwe_root


def test_complete_corpus_and_repeat_load_preserve_sources():
    ids = set()
    for key, (filename, scanner, _, count) in DATASETS.items():
        first = load_dataset(key)
        assert first['normalized'] + first['normalized_with_warnings'] == count
        second = load_dataset(key)
        assert second['already_loaded'] == count
        assert second['normalized'] + second['normalized_with_warnings'] == 0
        assert second['finding_ids'] == first['finding_ids']
        ids.update(first['finding_ids'])
        original = json.loads((DATA_DIR / filename).read_text())
        raw = [r for run in original['runs'] for r in run['results']] if filename.endswith('.sarif') else original
        for fid, source_record in zip(first['finding_ids'], raw):
            finding = repo.get_normalized_finding(fid)
            assert finding.source_scanner == scanner
            assert finding.vulnerability.title != 'Untitled Vulnerability'
            assert resolve_cwe_root(finding.vulnerability.cwe_primary) in {'CWE-89', 'CWE-79', 'CWE-918'}
            assert finding.vulnerability.severity != 'Unknown'
            assert finding.location.host
            assert finding.provenance.original_data == source_record
            if filename.endswith('.sarif'):
                assert finding.provenance.parser_name == 'GenericSARIFParser'
                assert finding.location.path and finding.location.parameter
    assert len(ids) == repo.count_normalized_findings() == 110


def test_concurrent_loads_share_batch_identity():
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(load_dataset, ['burp-ssrf', 'burp-ssrf']))
    assert results[0]['finding_ids'] == results[1]['finding_ids']
    assert sorted(r['already_loaded'] for r in results) == [0, 10]
    assert repo.count_normalized_findings() == 10


def test_failed_load_rolls_back_and_can_retry(monkeypatch):
    original = normalizer_service.normalize_record
    calls = 0
    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError('Injected normalization failure')
        return original(*args, **kwargs)
    with monkeypatch.context() as context:
        context.setattr(normalizer_service, 'normalize_record', fail_second)
        with pytest.raises(ValueError):
            load_dataset('burp-ssrf')
    with get_db() as db:
        assert db.execute('SELECT COUNT(*) FROM scanner_findings').fetchone()[0] == 0
    assert repo.count_normalized_findings() == 0
    assert len(load_dataset('burp-ssrf')['finding_ids']) == 10

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
    assert set(metrics) == {'findings','active_issues','clusters','priorities','validations','artifacts'}
