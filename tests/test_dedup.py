"""
tests/test_dedup.py — Unit tests for deduplication engine.
"""

from datetime import datetime, timezone
import pytest

from src.app.schemas.canonical import (
    NormalizedFinding, VulnerabilityInfo, AssetInfo, LocationInfo,
    EvidenceInfo, RemediationInfo, ProvenanceInfo, QualityInfo, SourceInfo
)
from src.app.services.normalizer import normalizer_service
from src.app.services.deduplicator import deduplicator_service
from src.app.repositories.findings_repo import repo as findings_repo


def test_fingerprint_dedup():
    records = [
        {"name": "Burp SQLi", "host": "https://app.example.test", "path": "/api/login", "parameter": "username", "severity": "High", "cwe": "89"},
        {"name": "Nessus SQLi", "host": "https://app.example.test", "path": "/api/login", "parameter": "username", "severity": "High", "cwe": "89"},
    ]

    summary = normalizer_service.normalize_batch(records, source_scanner="burp")
    assert summary.normalized + summary.normalized_with_warnings == 2

    dedup_summary = deduplicator_service.run_deduplication()
    assert dedup_summary.total_findings_processed >= 2
    assert dedup_summary.deterministic_clusters_created >= 1
    assert dedup_summary.total_canonical_issues >= 1


def test_hard_block_different_params():
    now_dt = datetime.now(timezone.utc)
    f1 = NormalizedFinding(
        finding_id="f-dup-1",
        fingerprint="fp1",
        source_scanner="burp",
        ingestion_batch_id="b1",
        ingested_at=now_dt,
        source=SourceInfo(tool_name="burp"),
        vulnerability=VulnerabilityInfo(title="SQLi username"),
        asset=AssetInfo(asset_name="app1"),
        location=LocationInfo(host="app1", path="/login", parameter="username"),
        evidence=EvidenceInfo(),
        remediation=RemediationInfo(),
        provenance=ProvenanceInfo(parser_name="p", raw_record_hash="h1"),
        quality=QualityInfo()
    )

    f2 = NormalizedFinding(
        finding_id="f-dup-2",
        fingerprint="fp2",
        source_scanner="burp",
        ingestion_batch_id="b1",
        ingested_at=now_dt,
        source=SourceInfo(tool_name="burp"),
        vulnerability=VulnerabilityInfo(title="SQLi password"),
        asset=AssetInfo(asset_name="app1"),
        location=LocationInfo(host="app1", path="/login", parameter="password"),
        evidence=EvidenceInfo(),
        remediation=RemediationInfo(),
        provenance=ProvenanceInfo(parser_name="p", raw_record_hash="h2"),
        quality=QualityInfo()
    )

    is_blocked = deduplicator_service._check_hard_blocks(f1, f2)
    assert is_blocked is True
