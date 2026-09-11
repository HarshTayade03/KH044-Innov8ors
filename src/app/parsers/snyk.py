"""
parsers/snyk.py — Parser for Snyk JSON vulnerability reports.
"""

from typing import Any
from src.app.parsers.base import BaseScannerParser, register_parser


class SnykParser(BaseScannerParser):
    scanner_name = "snyk"

    def parse(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        pkg_name = raw_record.get("package_name") or raw_record.get("pkgName") or raw_record.get("packageName")
        pkg_version = raw_record.get("package_version") or raw_record.get("version")
        title = raw_record.get("title") or (f"Vulnerability in {pkg_name}" if pkg_name else "Snyk Finding")

        cve = raw_record.get("cve") or raw_record.get("identifiers", {}).get("CVE", [])
        if isinstance(cve, str):
            cve_ids = [cve]
        elif isinstance(cve, list):
            cve_ids = cve
        else:
            cve_ids = []

        cwe = raw_record.get("cwe") or raw_record.get("identifiers", {}).get("CWE", [])
        if isinstance(cwe, str):
            cwe_ids = [cwe]
        elif isinstance(cwe, list):
            cwe_ids = cwe
        else:
            cwe_ids = []

        fixed_in = raw_record.get("fixed_in") or raw_record.get("fixedIn") or []
        fixed_ver = fixed_in[0] if (isinstance(fixed_in, list) and fixed_in) else (str(fixed_in) if fixed_in else None)

        cvss_score = raw_record.get("cvss_score") or raw_record.get("cvssScore")

        return {
            "title": title,
            "description": raw_record.get("description"),
            "cve_ids": cve_ids,
            "cwe_ids": cwe_ids,
            "severity_raw": raw_record.get("severity"),
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "package": pkg_name,
            "installed_version": pkg_version,
            "fixed_version": fixed_ver,
            "file": raw_record.get("file") or raw_record.get("from", [None])[0],
            "asset_name": pkg_name or raw_record.get("file") or "Snyk Asset",
            "asset_type": "library",
            "source_finding_id": str(raw_record.get("id")) if raw_record.get("id") else None,
            "original_record": raw_record,
        }


snyk_parser = SnykParser()
register_parser("snyk", snyk_parser)
