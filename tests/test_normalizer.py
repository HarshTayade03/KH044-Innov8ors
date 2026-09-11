"""
tests/test_normalizer.py — Unit tests for normalizer service and API contracts.
Defined according to docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

import pytest
from src.app.services.normalizer import normalizer_service
from src.app.schemas.canonical import ManualFindingCreate


def test_normalize_single_record():
    raw = {
        "plugin_id": 1001,
        "plugin_name": "SQL Injection in /api/login",
        "host": "app.example.test",
        "severity": "High",
        "cvss_base_score": 8.8,
        "cve": ["CVE-2024-1001"]
    }
    finding = normalizer_service.normalize_record(
        raw_record=raw,
        source_scanner="nessus",
        ingestion_batch_id="batch-test-001"
    )
    assert finding.finding_id.startswith("f-")
    assert finding.vulnerability.severity == "High"
    assert finding.vulnerability.cvss_score == 8.8
    assert finding.vulnerability.cwe_primary == "CWE-89"
    assert finding.quality.normalization_status == "normalized"
    assert finding.quality.completeness_score >= 0.7


test_manual_entry_payload = ManualFindingCreate(
    title="Manual SQL Injection Finding",
    description="Found via manual inspection during penetration test.",
    severity="Critical",
    asset_name="app.example.test",
    url="https://app.example.test/api/checkout",
    parameter="coupon",
    cwe_ids=["CWE-89"],
    cve_ids=["CVE-2024-9999"],
)


def test_normalize_manual_entry():
    finding = normalizer_service.normalize_manual_entry(test_manual_entry_payload)
    assert finding.vulnerability.title == "Manual SQL Injection Finding"
    assert finding.vulnerability.severity == "Critical"
    assert finding.location.parameter == "coupon"
    assert finding.vulnerability.cwe_primary == "CWE-89"


def test_batch_normalization():
    records = [
        {"name": "Burp SQLi 1", "host": "https://app.example.test", "path": "/api/v1", "parameter": "id", "severity": "High"},
        {"name": "Burp XSS 2", "host": "https://app.example.test", "path": "/search", "parameter": "q", "severity": "Medium"},
    ]
    summary = normalizer_service.normalize_batch(records=records, source_scanner="burp")
    assert summary.total_received == 2
    assert summary.normalized + summary.normalized_with_warnings == 2
    assert summary.rejected == 0
