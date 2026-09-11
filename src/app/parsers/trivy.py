"""
parsers/trivy.py — Parser for Trivy JSON vulnerability reports.
"""

from typing import Any
from src.app.parsers.base import BaseScannerParser, register_parser


class TrivyParser(BaseScannerParser):
    scanner_name = "trivy"

    def parse(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        vuln_id = raw_record.get("vulnerability_id") or raw_record.get("VulnerabilityID")
        pkg_name = raw_record.get("pkg_name") or raw_record.get("PkgName")
        title = raw_record.get("title") or raw_record.get("Title") or vuln_id or "Trivy Finding"

        cve_ids = [vuln_id] if (vuln_id and vuln_id.startswith("CVE-")) else []

        cwe = raw_record.get("cwe_ids") or raw_record.get("CweIDs") or []
        if isinstance(cwe, str):
            cwe_ids = [cwe]
        elif isinstance(cwe, list):
            cwe_ids = cwe
        else:
            cwe_ids = []

        cvss_score = raw_record.get("cvss_score") or raw_record.get("CVSS", {}).get("nvd", {}).get("V3Score")

        primary_url = raw_record.get("primary_url") or raw_record.get("PrimaryURL")

        return {
            "title": title,
            "description": raw_record.get("description") or raw_record.get("Description"),
            "cve_ids": cve_ids,
            "cwe_ids": cwe_ids,
            "severity_raw": raw_record.get("severity") or raw_record.get("Severity"),
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "package": pkg_name,
            "installed_version": raw_record.get("installed_version") or raw_record.get("InstalledVersion"),
            "fixed_version": raw_record.get("fixed_version") or raw_record.get("FixedVersion"),
            "container_image": raw_record.get("target") or raw_record.get("Target"),
            "asset_name": raw_record.get("target") or pkg_name or "Trivy Container Asset",
            "asset_type": "container" if raw_record.get("target") else "library",
            "reference_urls": [primary_url] if primary_url else [],
            "source_finding_id": vuln_id,
            "original_record": raw_record,
        }


trivy_parser = TrivyParser()
register_parser("trivy", trivy_parser)
