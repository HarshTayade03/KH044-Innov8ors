"""
parsers/burp.py — Parser for Burp Suite flat JSON findings.
Defined according to docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

from typing import Any
from urllib.parse import urlparse
from src.app.parsers.base import BaseScannerParser, register_parser, BURP_RULE_TO_CWE


class BurpParser(BaseScannerParser):
    scanner_name = "burp"

    def parse(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        title = raw_record.get("title") or raw_record.get("name") or raw_record.get("issue_name") or "Burp Suite Finding"
        description = raw_record.get("issue_background") or raw_record.get("description") or raw_record.get("issue_detail")

        # Location parsing
        host = raw_record.get("host") or ""
        path = raw_record.get("path")
        url = raw_record.get("url")

        if not url and host:
            url = f"{host}{path}" if path else host

        if url and not path:
            parsed = urlparse(url)
            path = parsed.path
            if not host:
                host = parsed.netloc

        parameter = raw_record.get("parameter")

        # CWE mapping from issue name or rule
        cwes = raw_record.get("cwe_ids") or []
        if not cwes:
            title_lower = title.lower()
            for rule_key, cwe in BURP_RULE_TO_CWE.items():
                if rule_key in title_lower or rule_key.replace("-", " ") in title_lower:
                    cwes.append(cwe)
                    break

        return {
            "title": title,
            "description": description,
            "cve_ids": raw_record.get("cve_ids", []),
            "cwe_ids": cwes,
            "severity_raw": raw_record.get("severity"),
            "confidence": raw_record.get("confidence"),
            "host": host,
            "url": url,
            "path": path,
            "parameter": parameter,
            "request": raw_record.get("request"),
            "response": raw_record.get("response"),
            "evidence_summary": raw_record.get("evidence") or raw_record.get("issue_detail"),
            "source_finding_id": str(raw_record.get("issue_id")) if raw_record.get("issue_id") else None,
            "asset_type": "web_application",
            "original_record": raw_record,
        }


burp_parser = BurpParser()
register_parser("burp", burp_parser)
