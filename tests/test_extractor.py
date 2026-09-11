"""
tests/test_extractor.py — Unit tests for multi-view extractor and embedding services.
"""

from datetime import datetime, timezone
import pytest

from src.app.schemas.canonical import (
    NormalizedFinding, VulnerabilityInfo, AssetInfo, LocationInfo,
    EvidenceInfo, RemediationInfo, ProvenanceInfo, QualityInfo, SourceInfo
)
from src.app.services.extractor import extractor_service, redact_secrets
from src.app.services.embedding import embedding_service, cosine_similarity, weighted_similarity


def create_mock_finding(
    cwe_primary="CWE-89",
    url="https://app.example.test/api/user/123/profile",
    param="user_id",
    request="POST /api/user/123/profile HTTP/1.1\nHost: app.example.test\nAuthorization: Bearer secret_token_123\n\nuser_id=1' OR '1'='1",
    payload="password=secret_pass123",
    severity="High"
) -> NormalizedFinding:
    now_dt = datetime.now(timezone.utc)
    return NormalizedFinding(
        finding_id="f-test-100",
        fingerprint="fp-test-100",
        source_scanner="burp",
        ingestion_batch_id="batch-test",
        ingested_at=now_dt,
        source=SourceInfo(tool_name="burp", original_severity_raw="High"),
        vulnerability=VulnerabilityInfo(
            title="SQL Injection in user_id parameter",
            description="The application appears to be vulnerable to SQL injection.",
            cwe_ids=[cwe_primary],
            cwe_primary=cwe_primary,
            severity=severity,
            cvss_score=7.5,
        ),
        asset=AssetInfo(asset_name="app.example.test", asset_type="web_application"),
        location=LocationInfo(
            host="app.example.test",
            protocol="https",
            url=url,
            path="/api/user/123/profile",
            parameter=param,
            parameter_class="id"
        ),
        evidence=EvidenceInfo(
            summary="SQL error observed in response password=secret_pass123",
            request=request,
            response="HTTP/1.1 500 Internal Server Error\n\nSyntax error in SQL statement",
            payload=payload
        ),
        remediation=RemediationInfo(recommendation="Use parameterized queries."),
        provenance=ProvenanceInfo(parser_name="BurpParser", raw_record_hash="hash123"),
        quality=QualityInfo(normalization_status="normalized", completeness_score=1.0)
    )



def test_secret_redaction():
    text = "Headers: Authorization: Bearer secret_123 and password=mysecretpass Cookie: session=abc"
    redacted = redact_secrets(text)
    assert "secret_123" not in redacted
    assert "<REDACTED>" in redacted
    assert "mysecretpass" not in redacted


def test_authorization_values_are_redacted():
    redacted = redact_secrets("Authorization: Bearer live-token Authorization: Basic dXNlcjpwYXNz")
    assert "live-token" not in redacted
    assert "dXNlcjpwYXNz" not in redacted
    assert redacted.count("<REDACTED>") == 2


def test_extract_views_sqli():
    finding = create_mock_finding()
    views = extractor_service.extract_views(finding)

    assert views.finding_id == "f-test-100"
    assert views.description.status == "available"
    assert "CWE-89" in views.description.text
    assert views.location.status == "available"
    assert views.location.structured["canonical_path"] == "/api/user/{id}/profile"
    assert views.reproduction.status == "available"
    assert "<REDACTED>" in views.reproduction.text
    assert views.impact.status in ("inferred", "available")
    assert "potential authentication bypass" in views.impact.text


def test_cosine_similarity():
    vec_a = [1.0, 0.0, 0.0]
    vec_b = [1.0, 0.0, 0.0]
    assert pytest.approx(cosine_similarity(vec_a, vec_b)) == 1.0

    vec_c = [0.0, 1.0, 0.0]
    assert pytest.approx(cosine_similarity(vec_a, vec_c)) == 0.0


def test_view_extraction_missing_fields():
    now_dt = datetime.now(timezone.utc)
    bare_finding = NormalizedFinding(
        finding_id="f-test-bare",
        fingerprint="fp-bare",
        source_scanner="manual",
        ingestion_batch_id="batch-bare",
        ingested_at=now_dt,
        source=SourceInfo(tool_name="manual"),
        vulnerability=VulnerabilityInfo(title="Untitled Vulnerability"),
        asset=AssetInfo(asset_name="unknown"),
        location=LocationInfo(),
        evidence=EvidenceInfo(),
        remediation=RemediationInfo(),
        provenance=ProvenanceInfo(parser_name="ManualParser", raw_record_hash="hashbare"),
        quality=QualityInfo(normalization_status="normalized")
    )

    views = extractor_service.extract_views(bare_finding)
    assert views.location.status == "partial"
    assert views.reproduction.status == "missing"
    assert views.view_quality.available_views < 4
