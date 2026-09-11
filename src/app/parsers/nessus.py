"""
parsers/nessus.py — Parser for Nessus JSON findings.
Defined according to docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

from typing import Any
from src.app.parsers.base import BaseScannerParser, register_parser, NESSUS_PLUGIN_TO_CWE


class NessusParser(BaseScannerParser):
    scanner_name = "nessus"

    def parse(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        plugin_name = raw_record.get("plugin_name") or raw_record.get("title") or "Nessus Finding"
        description = raw_record.get("description") or raw_record.get("synopsis")

        # CVE handling (string or list)
        cves = raw_record.get("cve") or raw_record.get("cve_ids") or []
        if isinstance(cves, str):
            cves = [cves]

        # Severity & CVSS
        severity_raw = raw_record.get("severity") or raw_record.get("risk_factor")
        cvss_score = raw_record.get("cvss_base_score") or raw_record.get("cvss3_base_score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        # CWE Inference from plugin_name if absent
        cwes = raw_record.get("cwe") or raw_record.get("cwe_ids") or []
        if isinstance(cwes, (str, int)):
            cwes = [str(cwes)]

        if not cwes:
            p_name_lower = plugin_name.lower()
            for kw, cwe in NESSUS_PLUGIN_TO_CWE:
                if kw in p_name_lower:
                    cwes.append(cwe)
                    break

        host = raw_record.get("host") or raw_record.get("hostname") or raw_record.get("ip") or "unknown_host"
        port = raw_record.get("port")
        if port is not None:
            try:
                port = int(port)
            except (ValueError, TypeError):
                port = None

        return {
            "title": plugin_name,
            "description": description,
            "cve_ids": cves,
            "cwe_ids": cwes,
            "severity_raw": severity_raw,
            "cvss_score": cvss_score,
            "host": host,
            "port": port,
            "protocol": raw_record.get("protocol"),
            # Preserve explicit web context from enriched Nessus exports. Dropping it
            # prevents cross-scanner matches and removes parameter merge protections.
            "url": raw_record.get("url"),
            "path": raw_record.get("path"),
            "parameter": raw_record.get("parameter"),
            "raw_output": raw_record.get("plugin_output") or raw_record.get("output"),
            "solution": raw_record.get("solution"),
            "source_finding_id": str(raw_record.get("plugin_id")) if raw_record.get("plugin_id") else None,
            "asset_type": "host" if host else "unknown",
            "original_record": raw_record,
        }


nessus_parser = NessusParser()
register_parser("nessus", nessus_parser)
