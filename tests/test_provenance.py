import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from src.app.config import settings
from src.app.main import app
from src.app.repositories.findings_repo import repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.services import embedding, deduplicator
from src.app.services.extractor import extractor_service
from src.app.services.risk_engine import risk_engine
from src.app.services.threat_intel import threat_intel_service, ThreatIntelUnavailable


def test_fallback_provenance_and_missing_view_replacement(finding_factory):
    finding = finding_factory()
    views = extractor_service.extract_views(finding)
    vectors = embedding.embedding_service.generate_embeddings(views)
    assert vectors.embedding_model == 'sha256-token-hashing'
    assert vectors.model_version == '1'
    repo.save_finding_embeddings(vectors)
    stored = repo.get_finding_embeddings(finding.finding_id)
    assert stored.embedding_model == vectors.embedding_model
    assert stored.input_text_hashes['description'] == hashlib.sha256(views.embedding_text['description'].encode()).hexdigest()
    views.embedding_text.pop('description')
    newer = embedding.embedding_service.generate_batch_embeddings([views])[0]
    repo.save_finding_embeddings(newer)
    assert 'description' in repo.get_finding_embeddings(finding.finding_id).missing_views


def test_model_load_failure_uses_explicit_fallback(monkeypatch):
    import sys
    from types import SimpleNamespace

    def unavailable(name, **kwargs):
        assert kwargs['local_files_only'] is True
        raise OSError('model not cached')

    monkeypatch.setattr(embedding, '_model', None)
    monkeypatch.setattr(settings, 'model_allow_download', False)
    monkeypatch.setitem(sys.modules, 'sentence_transformers', SimpleNamespace(SentenceTransformer=unavailable))
    assert isinstance(embedding.get_embedding_model(), embedding.FallbackEmbedder)


def test_missing_sklearn_is_reported(finding_factory, monkeypatch):
    finding_factory(parameter='username')
    finding_factory(parameter='password')
    monkeypatch.setattr(deduplicator, 'HAS_SKLEARN', False)
    result = deduplicator.deduplicator_service.run_deduplication()
    assert result.semantic_status == 'unavailable'
    assert result.warnings
    assert len(dedup_repo.list_canonical_issues()) == 2


def test_mock_cache_refreshes_on_content_change(tmp_path, monkeypatch):
    epss = tmp_path / 'epss.json'
    monkeypatch.setattr(settings, 'epss_data_path', str(epss))
    epss.write_text(json.dumps({'data': [{'cve': 'CVE-2021-44228', 'epss': '0.1', 'percentile': '0.2'}]}))
    first = threat_intel_service.enrich_cve('CVE-2021-44228')
    cached = threat_intel_service.enrich_cve('CVE-2021-44228')
    assert cached.fetched_at == first.fetched_at
    epss.write_text(json.dumps({'data': [{'cve': 'CVE-2021-44228', 'epss': '0.9', 'percentile': '0.9'}]}))
    refreshed = threat_intel_service.enrich_cve('CVE-2021-44228')
    assert refreshed.epss_score == 0.9
    assert refreshed.source_fingerprint != first.source_fingerprint
    assert refreshed.data_source == 'mock'


@pytest.mark.parametrize('flag', ['kev_live', 'epss_live'])
def test_live_mode_rejected_even_after_cache_hit(flag, monkeypatch):
    threat_intel_service.enrich_cve('CVE-2021-44228')
    monkeypatch.setattr(settings, flag, True)
    with pytest.raises(ThreatIntelUnavailable, match='not implemented'):
        threat_intel_service.enrich_cve('CVE-2021-44228')


@pytest.mark.parametrize('contents', ['not json', '{}', '{"data": [{"cve":"CVE-2021-44228","epss":5}]}'])
def test_bad_feed_never_becomes_clean_result(tmp_path, monkeypatch, contents):
    epss = tmp_path / 'epss.json'
    epss.write_text(contents)
    monkeypatch.setattr(settings, 'epss_data_path', str(epss))
    with pytest.raises(ThreatIntelUnavailable):
        threat_intel_service.enrich_cve('CVE-2021-44228')


def test_risk_explains_every_contribution_and_live_mode(finding_factory, monkeypatch):
    finding_factory()
    deduplicator.deduplicator_service.run_deduplication()
    issue = dedup_repo.list_canonical_issues()[0]
    result = risk_engine.calculate_priority(issue.canonical_issue_id)
    assert round(sum(result.factors['contributions'].values()), 2) == result.risk_score
    assert len(result.factors['contributions']) == 6
    assert result.factors['validation_status'] == 'not_attempted'
    assert result.factors['threat_source'] == 'mock'
    assert any('neutral' in line for line in result.explanation)
    again = risk_engine.calculate_priority(issue.canonical_issue_id)
    assert again.priority_id == result.priority_id
    monkeypatch.setattr(settings, 'kev_live', True)
    with TestClient(app) as client:
        assert client.post(f'/api/v1/canonical-issues/{issue.canonical_issue_id}/prioritize').status_code == 503
