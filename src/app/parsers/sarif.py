"""
parsers/sarif.py — Parser for SARIF 2.1.0 (Burp/Nessus SARIF) and OWASP ZAP JSON format.
Defined according to docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

from typing import Any
from urllib.parse import urlparse
from src.app.parsers.base import BaseScannerParser, register_parser, BURP_RULE_TO_CWE


class GenericSARIFParser(BaseScannerParser):
    scanner_name = "sarif"

    def parse(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        """
        Parses a single SARIF result object.
        """
        rule_id = raw_record.get("ruleId") or raw_record.get("rule", {}).get("id") or "sarif_rule"
        message_obj = raw_record.get("message", {})
        description = message_obj.get("text") or message_obj.get("markdown") if isinstance(message_obj, dict) else str(message_obj)
        title = raw_record.get("title") or description or f"SARIF Finding ({rule_id})"
        if len(title) > 100:
            title = f"{title[:97]}..."

        # Locations
        locations = raw_record.get("locations", [])
        uri = None
        start_line = None
        if locations and isinstance(locations, list):
            loc = locations[0]
            phys = loc.get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            uri = art.get("uri")
            reg = phys.get("region", {})
            start_line = reg.get("startLine")

        props = raw_record.get("properties", {})
        if not isinstance(props, dict):
            props = {}

        # CWE Resolution from rule_id or properties
        cwes = props.get("cwe_ids") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        if not cwes:
            rule_lower = rule_id.lower()
            for key, cwe in BURP_RULE_TO_CWE.items():
                if key in rule_lower:
                    cwes.append(cwe)
                    break
            if not cwes and "CWE-" in rule_id:
                cwes.append(rule_id)

        # Host, path, parameter extraction from properties or uri
        host = props.get("host")
        path = props.get("path")
        parameter = props.get("parameter")
        url = props.get("url") or uri

        if url and not path:
            parsed = urlparse(url)
            path = parsed.path
            if not host:
                host = parsed.netloc

        level = raw_record.get("level", "error")

        return {
            "title": title,
            "description": description,
            "cve_ids": props.get("cve_ids", []),
            "cwe_ids": cwes,
            "severity_raw": level,
            "confidence": props.get("confidence"),
            "host": host,
            "url": url,
            "path": path,
            "parameter": parameter,
            "file": uri if not (url and url.startswith("http")) else None,
            "request": props.get("request"),
            "response": props.get("response"),
            "evidence_summary": props.get("evidence") or description,
            "source_finding_id": rule_id,
            "asset_type": "web_application" if (url or host) else "host",
            "original_record": raw_record,
        }


class ZAPParser(BaseScannerParser):
    scanner_name = "zap"

    def parse(self, raw_record: dict[str, Any]) -> dict[str, Any]:
        """
        Parses OWASP ZAP JSON alert format.
        """
        title = raw_record.get("alert") or raw_record.get("name") or "OWASP ZAP Finding"
        description = raw_record.get("description")
        riskcode = raw_record.get("riskcode") or raw_record.get("risk")

        url = raw_record.get("url")
        path = None
        host = None
        if url:
            parsed = urlparse(url)
            path = parsed.path
            host = parsed.netloc

        parameter = raw_record.get("param") or raw_record.get("parameter")
        cweid = raw_record.get("cweid") or raw_record.get("cwe")
        cwe_ids = [f"CWE-{cweid}"] if cweid else []

        return {
            "title": title,
            "description": description,
            "cve_ids": raw_record.get("cve_ids", []),
            "cwe_ids": cwe_ids,
            "severity_raw": riskcode,
            "confidence": raw_record.get("confidence"),
            "host": host,
            "url": url,
            "path": path,
            "parameter": parameter,
            "payload": raw_record.get("attack"),
            "evidence_summary": raw_record.get("evidence"),
            "solution": raw_record.get("solution"),
            "source_finding_id": str(raw_record.get("alertRef")) if raw_record.get("alertRef") else None,
            "asset_type": "web_application",
            "original_record": raw_record,
        }


sarif_parser = GenericSARIFParser()
register_parser("sarif", sarif_parser)

zap_parser = ZAPParser()
register_parser("zap", zap_parser)
