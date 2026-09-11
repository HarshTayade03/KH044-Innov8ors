"""
parsers/base.py — Abstract parser base class, scanner registry, lookup mappings, and normalization functions.

Defined according to docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

from abc import ABC, abstractmethod
import hashlib
import re
from typing import Any, Optional


# ── Lookup Mappings ────────────────────────────────────────────────────────────

BURP_RULE_TO_CWE: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "csrf": "CWE-352",
    "xxe": "CWE-611",
    "path-traversal": "CWE-22",
    "open-redirect": "CWE-601",
    "rce": "CWE-78",
    "info-disclosure": "CWE-200",
    "broken-auth": "CWE-287",
}

NESSUS_PLUGIN_TO_CWE: list[tuple[str, str]] = [
    ("sql injection", "CWE-89"),
    ("cross-site scripting", "CWE-79"),
    ("xss", "CWE-79"),
    ("server-side request forgery", "CWE-918"),
    ("ssrf", "CWE-918"),
    ("path traversal", "CWE-22"),
    ("directory traversal", "CWE-22"),
    ("remote code execution", "CWE-78"),
    ("command injection", "CWE-77"),
    ("authentication bypass", "CWE-287"),
    ("ssl", "CWE-326"),
    ("tls", "CWE-326"),
    ("csrf", "CWE-352"),
    ("information disclosure", "CWE-200"),
]

CWE_PARENT_MAP: dict[str, str] = {
    "CWE-564": "CWE-89",   # Hibernate SQL Injection -> SQL Injection
    "CWE-80": "CWE-79",    # Basic XSS variant -> XSS
    "CWE-81": "CWE-79",    # Neutralization in error message -> XSS
    "CWE-85": "CWE-79",    # Doubled character XSS -> XSS
    "CWE-86": "CWE-79",    # Neutralization of invalid characters -> XSS
    "CWE-87": "CWE-79",    # Alternate XSS syntax -> XSS
    "CWE-918": "CWE-918",  # SSRF is root
    "CWE-639": "CWE-285",  # IDOR -> Improper Authorization
}


# ── Normalization Utilities ───────────────────────────────────────────────────

def normalize_cve(raw: Optional[str]) -> Optional[str]:
    """
    Normalize CVE string variants: 'cve-2024-1234', 'CVE 2024 1234', 'CVE_2024_1234', URLs
    Output: 'CVE-2024-1234' or None if unparseable.
    """
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    match = re.search(r"CVE[-_\s]?(\d{4})[-_\s]?(\d{4,})", cleaned, re.IGNORECASE)
    if match:
        return f"CVE-{match.group(1)}-{match.group(2)}"
    return None


def normalize_cwe(raw: Any) -> Optional[str]:
    """
    Normalize CWE variants: 89, '89', 'CWE89', 'cwe-89', 'CWE 89', 'CWE-0089'
    Output: 'CWE-89'
    """
    if raw is None:
        return None
    raw_str = str(raw).strip()
    match = re.search(r"(?:CWE[-_\s]?)?0*(\d+)", raw_str, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return None


def resolve_cwe_root(cwe_id: Optional[str]) -> Optional[str]:
    """Resolve a CWE to its root parent if mapped in CWE_PARENT_MAP."""
    if not cwe_id:
        return None
    norm = normalize_cwe(cwe_id)
    if not norm:
        return None
    return CWE_PARENT_MAP.get(norm, norm)


def normalize_severity(raw: Any) -> tuple[str, str]:
    """
    Returns (canonical_severity, source_type).
    Canonical severity: Critical | High | Medium | Low | Informational | Unknown
    """
    if raw is None:
        return ("Unknown", "tool")

    val = str(raw).strip().lower()

    # ZAP riskcode check (string "0", "1", "2", "3")
    if val == "3":
        return ("High", "tool")
    elif val == "2":
        return ("Medium", "tool")
    elif val == "1":
        return ("Low", "tool")
    elif val == "0":
        return ("Informational", "tool")

    # Numerical severity (CVSS score)
    try:
        score = float(val)
        if score >= 9.0:
            return ("Critical", "tool")
        elif score >= 7.0:
            return ("High", "tool")
        elif score >= 4.0:
            return ("Medium", "tool")
        elif score > 0.0:
            return ("Low", "tool")
        else:
            return ("Informational", "tool")
    except ValueError:
        pass

    # Qualitative mapping
    if "critical" in val:
        return ("Critical", "tool")
    elif "high" in val or "error" in val:
        return ("High", "tool")
    elif "med" in val or "warning" in val:
        return ("Medium", "tool")
    elif "low" in val or "note" in val:
        return ("Low", "tool")
    elif "info" in val or "none" in val:
        return ("Informational", "tool")
    else:
        return ("Unknown", "tool")


def derive_cvss_from_severity(severity: str) -> tuple[float, float]:
    """
    Returns (derived_cvss_score, confidence) for findings with qualitative severity but no CVSS score.
    """
    mapping = {
        "Critical": (9.5, 0.5),
        "High": (7.5, 0.5),
        "Medium": (5.0, 0.5),
        "Low": (2.0, 0.5),
        "Informational": (0.0, 0.3),
        "Unknown": (0.0, 0.1),
    }
    return mapping.get(severity, (0.0, 0.1))


def infer_parameter_class(param_name: Optional[str]) -> Optional[str]:
    """Classifies parameter into id / auth / redirect / file / generic."""
    if not param_name:
        return None
    name = param_name.strip().lower()
    if re.search(r"^(id|user_?id|product_?id|uid|account_?id)$", name):
        return "id"
    elif re.search(r"(token|password|passwd|pwd|key|auth|apikey|session|secret)", name):
        return "auth"
    elif re.search(r"(url|redirect|return|next|callback|target|dest)", name):
        return "redirect"
    elif re.search(r"(file|path|filename|upload|attachment|doc)", name):
        return "file"
    else:
        return "generic"


def canonicalize_path(url_or_path: Optional[str]) -> str:
    """Collapses numeric segments (/user/123/posts -> /user/{id}/posts)."""
    if not url_or_path:
        return "NO_PATH"
    # Strip query string
    path = url_or_path.split("?")[0].strip()
    # Strip scheme and host if full URL
    path = re.sub(r"^https?://[^/]+", "", path)
    if not path:
        return "NO_PATH"
    # Collapse numeric IDs
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return path.lower()


def compute_fingerprint(cwe_primary: Optional[str], url_or_path: Optional[str], parameter_class: Optional[str]) -> str:
    """
    Deterministically computes SHA-256 fingerprint from (cwe_primary + canonical_path + parameter_class).
    """
    cwe_root = resolve_cwe_root(cwe_primary) or "NO_CWE"
    c_path = canonicalize_path(url_or_path)
    p_class = parameter_class or "NO_PARAM"
    key = f"{cwe_root}|{c_path}|{p_class}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def compute_completeness(finding_dict: dict[str, Any]) -> float:
    """Computes fraction (0.0-1.0) of 7 required fields present."""
    vuln = finding_dict.get("vulnerability", {})
    asset = finding_dict.get("asset", {})
    loc = finding_dict.get("location", {})
    ev = finding_dict.get("evidence", {})
    prov = finding_dict.get("provenance", {})

    checks = [
        bool(vuln.get("title")),
        bool(vuln.get("severity") and vuln.get("severity") != "Unknown"),
        bool(asset.get("asset_name")),
        bool(loc.get("host") or loc.get("url") or loc.get("path") or loc.get("package") or loc.get("file")),
        bool(ev.get("summary") or ev.get("request") or ev.get("raw_output")),
        bool(prov.get("raw_record_hash")),
        bool(vuln.get("cwe_ids") or vuln.get("cve_ids")),
    ]
    return round(sum(checks) / len(checks), 2)


# ── Base Parser Interface & Registry ──────────────────────────────────────────

class BaseScannerParser(ABC):
    scanner_name: str

    @abstractmethod
    def parse(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        """
        Parse raw scanner record into intermediate dictionary for normalizer.
        """
        pass

    def parse_batch(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse batch of records, isolating failures."""
        results = []
        for idx, raw in enumerate(records):
            try:
                results.append(self.parse(raw))
            except Exception as e:
                results.append({
                    "__parse_error__": str(e),
                    "__record_index__": idx,
                    "__raw__": raw,
                })
        return results


PARSER_REGISTRY: dict[str, BaseScannerParser] = {}


def register_parser(scanner_name: str, parser: BaseScannerParser) -> None:
    PARSER_REGISTRY[scanner_name.lower()] = parser


def get_parser(scanner_name: str) -> Optional[BaseScannerParser]:
    return PARSER_REGISTRY.get(scanner_name.lower())
