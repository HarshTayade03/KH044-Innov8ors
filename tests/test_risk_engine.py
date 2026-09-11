"""
tests/test_risk_engine.py — Unit tests for threat intelligence and risk prioritization engine.
"""

import pytest
from src.app.services.threat_intel import threat_intel_service
from src.app.services.normalizer import normalizer_service
from src.app.services.deduplicator import deduplicator_service
from src.app.services.risk_engine import risk_engine
from src.app.schemas.risk import RemediationTier
from src.app.repositories.dedup_repo import dedup_repo


def test_threat_intel_enrichment():
    enrichment = threat_intel_service.enrich_cve("CVE-2021-44228")
    assert enrichment.cve_id == "CVE-2021-44228"
    assert enrichment.kev_flag is True
    assert enrichment.epss_score > 0.90


def test_risk_scoring_immediate_tier():
    raw_record = {
        "title": "Log4j RCE in Production API",
        "severity": "Critical",
        "cvss_score": 10.0,
        "cve_ids": ["CVE-2021-44228"],
        "cwe_ids": ["CWE-78"],
        "host": "prod-api.example.test",
        "path": "/api/v1/log4j_test"
    }
    batch = normalizer_service.normalize_batch([raw_record], source_scanner="nessus")
    assert batch.normalized + batch.normalized_with_warnings == 1

    deduplicator_service.run_deduplication()

    issues = dedup_repo.list_canonical_issues()
    log4j_issue = next(i for i in issues if "Log4j RCE in Production API" in i.title)

    priority = risk_engine.calculate_priority(log4j_issue.canonical_issue_id)
    assert priority.risk_score >= 75.0
    assert priority.remediation_tier == RemediationTier.IMMEDIATE
    assert len(priority.explanation) > 0


def test_risk_scoring_standard_tier():
    raw_record = {
        "title": "Low Info Disclosure Unique Endpoint",
        "severity": "Low",
        "cvss_score": 2.0,
        "cwe_ids": ["CWE-200"],
        "host": "internal-standalone.test",
        "path": "/info_standalone_test"
    }
    batch = normalizer_service.normalize_batch([raw_record], source_scanner="burp")
    assert batch.normalized + batch.normalized_with_warnings == 1

    deduplicator_service.run_deduplication()

    issues = dedup_repo.list_canonical_issues()
    low_issue = next(i for i in issues if "Low Info Disclosure Unique Endpoint" in i.title)

    priority = risk_engine.calculate_priority(low_issue.canonical_issue_id)
    assert priority.risk_score < 50.0
    assert priority.remediation_tier == RemediationTier.STANDARD
