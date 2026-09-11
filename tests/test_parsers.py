"""
tests/test_parsers.py — Unit tests for scanner parsers (Nessus, Burp, ZAP, Snyk, Trivy, SARIF).
Defined according to docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

import pytest
from src.app.parsers.base import (
    normalize_cve,
    normalize_cwe,
    normalize_severity,
    derive_cvss_from_severity,
    compute_fingerprint,
    canonicalize_path,
    infer_parameter_class,
    get_parser,
)
from src.app.parsers.nessus import NessusParser
from src.app.parsers.burp import BurpParser
from src.app.parsers.sarif import GenericSARIFParser, ZAPParser
from src.app.parsers.snyk import SnykParser
from src.app.parsers.trivy import TrivyParser


def test_normalize_cve_variants():
    assert normalize_cve("cve-2024-1234") == "CVE-2024-1234"
    assert normalize_cve("CVE 2024 1234") == "CVE-2024-1234"
    assert normalize_cve("CVE_2024_1234") == "CVE-2024-1234"
    assert normalize_cve("https://cve.org/CVE-2024-1234") == "CVE-2024-1234"
    assert normalize_cve("invalid-cve") is None


def test_normalize_cwe_variants():
    assert normalize_cwe("89") == "CWE-89"
    assert normalize_cwe(89) == "CWE-89"
    assert normalize_cwe("CWE89") == "CWE-89"
    assert normalize_cwe("cwe-89") == "CWE-89"
    assert normalize_cwe("CWE-0089") == "CWE-89"
    assert normalize_cwe(None) is None


def test_normalize_severity():
    assert normalize_severity("High") == ("High", "tool")
    assert normalize_severity("CRITICAL") == ("Critical", "tool")
    assert normalize_severity(8.8) == ("High", "tool")
    assert normalize_severity("3") == ("High", "tool")
    assert normalize_severity("warning") == ("Medium", "tool")
    assert normalize_severity(None) == ("Unknown", "tool")


def test_derive_cvss():
    score, conf = derive_cvss_from_severity("High")
    assert score == 7.5
    assert conf == 0.5


def test_fingerprint_determinism():
    fp1 = compute_fingerprint("CWE-89", "/api/user/123", "id")
    fp2 = compute_fingerprint("CWE-89", "/api/user/456", "id")
    # Same canonical path (/api/user/{id}) and param_class -> identical fingerprint
    assert fp1 == fp2


def test_fingerprint_diff_param():
    fp1 = compute_fingerprint("CWE-89", "/api/user", "id")
    fp2 = compute_fingerprint("CWE-89", "/api/user", "generic")
    assert fp1 != fp2


def test_nessus_parser():
    parser = NessusParser()
    raw = {
        "plugin_id": 19506,
        "plugin_name": "Apache HTTP Backend SQL Injection in /api/login",
        "host": "10.0.0.15",
        "severity": "High",
        "cvss_base_score": 8.8,
        "cve": ["CVE-2024-1234"]
    }
    parsed = parser.parse(raw)
    assert parsed["title"] == "Apache HTTP Backend SQL Injection in /api/login"
    assert "CWE-89" in parsed["cwe_ids"]
    assert parsed["cvss_score"] == 8.8


def test_burp_sarif_parser():
    parser = GenericSARIFParser()
    raw = {
        "ruleId": "sqli",
        "message": {"text": "SQL Injection in /api/login"},
        "level": "error",
        "properties": {
            "host": "https://app.example.test",
            "path": "/api/login",
            "parameter": "username",
            "request": "POST /api/login username=admin"
        }
    }
    parsed = parser.parse(raw)
    assert parsed["source_finding_id"] == "sqli"
    assert "CWE-89" in parsed["cwe_ids"]
    assert parsed["parameter"] == "username"


def test_zap_parser():
    parser = ZAPParser()
    raw = {
        "alertRef": "40012",
        "alert": "Cross Site Scripting (Reflected)",
        "riskcode": "3",
        "url": "https://app.example.test/search?q=test",
        "param": "q",
        "cweid": "79"
    }
    parsed = parser.parse(raw)
    assert parsed["title"] == "Cross Site Scripting (Reflected)"
    assert parsed["cwe_ids"] == ["CWE-79"]
    assert parsed["severity_raw"] == "3"
