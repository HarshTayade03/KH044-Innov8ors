import itertools

import pytest
from fastapi.testclient import TestClient

from src.app.database import get_db
from src.app.main import app
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.risk_repo import risk_repo
from src.app.services.deduplicator import deduplicator_service as engine
from src.app.services.risk_engine import risk_engine


@pytest.mark.parametrize('field,values', [
    ('asset', ('app-a', 'app-b')), ('host', ('host-a', 'host-b')),
    ('package', ('pkg-a', 'pkg-b')), ('parameter', ('username', 'password')),
    ('parameter', ('ID', 'id')),
])
def test_equal_fingerprint_cannot_bypass_hard_blocks(finding_factory, field, values):
    first, second = finding_factory(), finding_factory()
    first.fingerprint = second.fingerprint = 'same-fingerprint'
    for finding, value in zip((first, second), values):
        if field == 'asset':
            finding.asset.asset_name = value
        else:
            setattr(finding.location, field, value)
    clusters, remaining = engine.stage_a_fingerprint_dedup([first, second])
    assert clusters == []
    assert len(remaining) == 2


def test_semantic_bridge_cannot_join_incompatible_members(finding_factory, monkeypatch):
    from src.app.services import deduplicator
    pytest.importorskip('sklearn')
    findings = [finding_factory(parameter=p) for p in ('username', None, 'password')]

    class BridgeClusterer:
        def __init__(self, **kwargs):
            pass

        def fit_predict(self, matrix):
            return [0, 0, 0]

    monkeypatch.setattr(deduplicator, 'HDBSCAN', BridgeClusterer)
    clusters = engine.stage_b_semantic_clustering(findings)
    by_id = {f.finding_id: f for f in findings}
    assert clusters
    for cluster in clusters:
        for a, b in itertools.combinations(cluster.members, 2):
            assert not engine._check_hard_blocks(by_id[a.finding_id], by_id[b.finding_id])


def test_rerun_split_merge_and_priorities(finding_factory):
    findings = [finding_factory(), finding_factory()]
    engine.run_deduplication()
    original = dedup_repo.list_canonical_issues()[0]
    risk_engine.calculate_priority(original.canonical_issue_id)
    engine.run_deduplication()
    assert [i.canonical_issue_id for i in dedup_repo.list_canonical_issues()] == [original.canonical_issue_id]
    with TestClient(app) as client:
        url = f'/api/v1/clusters/{original.cluster_id}'
        split = client.post(url + '/split')
        assert split.status_code == 200
        assert client.post(url + '/split').json() == split.json()
        assert risk_repo.get_priority_by_issue(original.canonical_issue_id) is None
        engine.run_deduplication()
        issues = dedup_repo.list_canonical_issues()
        assert len(issues) == 2
        assert {fid for i in issues for fid in i.source_finding_ids} == {f.finding_id for f in findings}
        assert client.post(url + '/merge').status_code == 200
        assert client.post(url + '/merge').status_code == 200
        engine.run_deduplication()
        assert len(dedup_repo.list_canonical_issues()) == 1
        assert client.post('/api/v1/clusters/missing/split').status_code == 404


def test_snapshot_failure_rolls_back(finding_factory, monkeypatch):
    finding_factory()
    engine.run_deduplication()
    old = dedup_repo.list_canonical_issues()[0]
    finding_factory()

    def fail(*args, **kwargs):
        raise RuntimeError('injected write failure')

    monkeypatch.setattr(dedup_repo, 'save_canonical_issue', fail)
    with pytest.raises(RuntimeError, match='injected'):
        engine.run_deduplication()
    assert [i.canonical_issue_id for i in dedup_repo.list_canonical_issues()] == [old.canonical_issue_id]
    with get_db() as db:
        assert db.execute('SELECT COUNT(*) FROM clusters').fetchone()[0] == 0


def test_concurrent_runs_publish_one_active_snapshot(finding_factory):
    from concurrent.futures import ThreadPoolExecutor
    finding_factory()
    finding_factory()
    with ThreadPoolExecutor(max_workers=2) as pool:
        summaries = list(pool.map(lambda _: engine.run_deduplication(), range(2)))
    assert all(s.total_canonical_issues == 1 for s in summaries)
    assert len(dedup_repo.list_canonical_issues()) == 1
    with get_db() as db:
        assert db.execute('SELECT COUNT(*) FROM clusters').fetchone()[0] == 1


def test_split_preserves_case_history_but_marks_it_stale(finding_factory):
    finding_factory()
    finding_factory()
    engine.run_deduplication()
    issue = dedup_repo.list_canonical_issues()[0]
    risk_engine.calculate_priority(issue.canonical_issue_id)
    with get_db() as db:
        db.execute('''INSERT INTO cases (case_id, canonical_issue_id, status, title,
                      created_at,last_updated_at,updated_at) VALUES (?,?,?,?,?,?,?)''',
                   ('case-1', issue.canonical_issue_id, 'approved', 'Reviewed case', 'now', 'now', 'now'))
    engine.review_cluster(issue.cluster_id, False)
    with get_db() as db:
        case = db.execute('SELECT * FROM cases WHERE case_id=?', ('case-1',)).fetchone()
        assert case['status'] == 'approved'
        assert case['stale'] == 1
        assert db.execute("SELECT COUNT(*) FROM audit_events WHERE action='retired'").fetchone()[0] == 1
    assert dedup_repo.get_canonical_issue(issue.canonical_issue_id).active is False
    with pytest.raises(ValueError):
        risk_engine.calculate_priority(issue.canonical_issue_id)


def test_new_duplicate_retires_old_singleton(finding_factory):
    finding_factory()
    engine.run_deduplication()
    first = dedup_repo.list_canonical_issues()[0]
    risk_engine.calculate_priority(first.canonical_issue_id)
    finding_factory()
    engine.run_deduplication()
    active = dedup_repo.list_canonical_issues()
    assert len(active) == 1
    assert len(active[0].source_finding_ids) == 2
    assert not dedup_repo.get_canonical_issue(first.canonical_issue_id).active
    assert risk_repo.get_priority_by_issue(first.canonical_issue_id) is None


def test_unsafe_legacy_cluster_cannot_be_merged(finding_factory):
    from src.app.schemas.dedup import ClusterMethod
    a, b = finding_factory(parameter='username'), finding_factory(parameter='password')
    cluster = engine._cluster([a, b], ClusterMethod.FINGERPRINT)
    dedup_repo.save_cluster(cluster)
    with TestClient(app) as client:
        response = client.post(f'/api/v1/clusters/{cluster.cluster_id}/merge')
        assert response.status_code == 409
    assert dedup_repo.list_canonical_issues() == []


def test_confirmed_merge_survives_new_ingestion(finding_factory):
    finding_factory()
    finding_factory()
    engine.run_deduplication()
    issue = dedup_repo.list_canonical_issues()[0]
    engine.review_cluster(issue.cluster_id, True)
    finding_factory()
    engine.run_deduplication()
    issues = dedup_repo.list_canonical_issues()
    assert len(issues) == 2
    assert dedup_repo.get_canonical_issue(issue.canonical_issue_id).active


def test_valid_cross_scanner_duplicate_merges():
    from src.app.services.normalizer import normalizer_service
    a = normalizer_service.normalize_record(
        {'name': 'SQL Injection', 'host': 'https://app.example.test', 'path': '/login', 'parameter': 'username', 'cwe_ids': ['CWE-89']},
        'burp', 'batch-burp')
    b = normalizer_service.normalize_record(
        {'plugin_name': 'SQL Injection', 'host': 'app.example.test', 'path': '/login', 'parameter': 'username', 'cwe': '89'},
        'nessus', 'batch-nessus')
    clusters, rest = engine.stage_a_fingerprint_dedup([a, b])
    assert len(clusters) == 1
    assert rest == []


def test_real_hdbscan_reports_backend_and_stable_issues(finding_factory):
    pytest.importorskip('sklearn')
    finding_factory(parameter='username')
    finding_factory(parameter='password')
    first = engine.run_deduplication()
    assert first.semantic_status == 'completed'
    assert first.embedding_models == ['sha256-token-hashing']
    ids = {i.canonical_issue_id for i in dedup_repo.list_canonical_issues()}
    assert len(ids) == 2
    engine.run_deduplication()
    assert ids == {i.canonical_issue_id for i in dedup_repo.list_canonical_issues()}
