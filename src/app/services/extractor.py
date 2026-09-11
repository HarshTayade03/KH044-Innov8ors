"""
services/extractor.py — Multi-View Extraction service.

Extracts 4 structured views (Description, Location, Reproduction, Impact) from canonical NormalizedFinding objects.
Defined according to docs/MODULE_SPECS/M2_views_embeddings.md.
"""

import re
from datetime import datetime, timezone
from typing import Optional, Any

from src.app.schemas.canonical import NormalizedFinding
from src.app.schemas.views import SingleView, FindingViews, ViewQuality, ViewStatus


# ── Secret Redaction ───────────────────────────────────────────────────────────

def redact_secrets(text: Optional[str]) -> Optional[str]:
    """
    Applies strict secret redaction rules to text before embedding/storage in views.
    """
    if not text:
        return text

    redacted = text
    redacted = re.sub(r"Authorization:\s*Bearer\s+\S+", "Authorization: Bearer <REDACTED>", redacted)
    redacted = re.sub(r"Authorization:\s*Basic\s+\S+", "Authorization: Basic <REDACTED>", redacted)
    redacted = re.sub(r"(?i)(password|passwd|pwd)[:=]\s*\S+", r"\1=<REDACTED>", redacted)
    redacted = re.sub(r"(?i)(api[_-]?key|apikey|x-api-key)[:=]\s*\S+", r"\1=<REDACTED>", redacted)
    redacted = re.sub(r"(?i)(token|access_token|auth_token)[:=]\s*\S+", r"\1=<REDACTED>", redacted)
    redacted = re.sub(r"Cookie:\s*.+", "Cookie: <REDACTED>", redacted)
    redacted = re.sub(r"Set-Cookie:\s*.+", "Set-Cookie: <REDACTED>", redacted)
    return redacted


# ── CWE Impact Mapping ─────────────────────────────────────────────────────────

CWE_IMPACT_MAP: dict[str, list[str]] = {
    "CWE-89": ["potential authentication bypass", "potential data disclosure", "potential data manipulation"],
    "CWE-79": ["potential cross-site scripting", "potential session hijacking", "potential credential theft"],
    "CWE-918": ["potential internal network access", "potential cloud metadata exposure", "potential SSRF-based RCE"],
    "CWE-22": ["potential arbitrary file read", "potential directory traversal"],
    "CWE-78": ["potential command execution", "potential remote code execution"],
    "CWE-639": ["potential unauthorized data access", "potential IDOR"],
    "CWE-352": ["potential CSRF", "potential unauthorized action on behalf of user"],
    "CWE-611": ["potential XXE", "potential file disclosure via XML"],
    "CWE-287": ["potential authentication bypass", "potential unauthorized access"],
    "CWE-200": ["potential sensitive information exposure"],
    "CWE-326": ["potential weak encryption", "potential traffic interception"],
}


class MultiViewExtractor:
    """Extracts 4 semantic views from NormalizedFinding instances."""

    def extract_description_view(self, finding: NormalizedFinding) -> SingleView:
        vuln = finding.vulnerability
        source_fields = []

        title = vuln.title if vuln.title and vuln.title != "Untitled Vulnerability" else None
        desc = vuln.description

        if title:
            source_fields.append("vulnerability.title")
        if desc:
            source_fields.append("vulnerability.description")
        if vuln.cwe_ids:
            source_fields.append("vulnerability.cwe_ids")
        if vuln.cve_ids:
            source_fields.append("vulnerability.cve_ids")

        if not title and not desc:
            return SingleView(
                text=None,
                structured={},
                source_fields=source_fields,
                extraction_method="missing",
                confidence=0.0,
                status=ViewStatus.MISSING,
                warnings=["Neither title nor description present in vulnerability info."]
            )

        # Text cleaning & boilerplate removal
        clean_desc = desc or ""
        clean_desc = re.sub(r"(?i)this plugin checks\.\.\.?", "", clean_desc)
        clean_desc = re.sub(r"(?i)the remote host is\.\.\.?", "", clean_desc)
        clean_desc = re.sub(r"(?i)this issue was identified by\.\.\.?", "", clean_desc)
        clean_desc = re.sub(r"\s+", " ", clean_desc).strip()

        combined_text_parts = []
        if title:
            combined_text_parts.append(title)
        if clean_desc:
            combined_text_parts.append(clean_desc)
        if vuln.cwe_primary:
            combined_text_parts.append(f"({vuln.cwe_primary})")
        if vuln.cve_ids:
            combined_text_parts.append(f"CVEs: {', '.join(vuln.cve_ids)}")

        full_text = " - ".join(combined_text_parts)
        if len(full_text) > 512:
            full_text = full_text[:509] + "..."

        text_redacted = redact_secrets(full_text)

        structured = {
            "title": title or (desc[:80] if desc else "Untitled"),
            "cwe_primary": vuln.cwe_primary,
            "cve_ids": vuln.cve_ids,
            "severity": vuln.severity,
        }

        if title and desc:
            status = ViewStatus.AVAILABLE
            confidence = 1.0
        elif title:
            status = ViewStatus.PARTIAL
            confidence = 0.7
        else:
            status = ViewStatus.PARTIAL
            confidence = 0.5

        return SingleView(
            text=text_redacted,
            structured=structured,
            source_fields=source_fields,
            extraction_method="structured_fields",
            confidence=confidence,
            status=status,
            warnings=[]
        )

    def extract_location_view(self, finding: NormalizedFinding) -> SingleView:
        loc = finding.location
        asset = finding.asset
        source_fields = []

        parts = []
        if asset.asset_name:
            parts.append(asset.asset_name)
            source_fields.append("asset.asset_name")
        if loc.protocol:
            parts.append(loc.protocol)
            source_fields.append("location.protocol")
        if loc.host:
            parts.append(loc.host)
            source_fields.append("location.host")
        if loc.port and loc.port not in (80, 443):
            parts.append(f"port:{loc.port}")
            source_fields.append("location.port")
        if loc.url or loc.path:
            p = loc.url or loc.path
            parts.append(p)
            source_fields.append("location.url" if loc.url else "location.path")
        if loc.parameter:
            parts.append(f"param:{loc.parameter}")
            source_fields.append("location.parameter")
        if loc.package:
            pkg_str = f"pkg:{loc.package}"
            if loc.installed_version:
                pkg_str += f":{loc.installed_version}"
                source_fields.append("location.installed_version")
            parts.append(pkg_str)
            source_fields.append("location.package")
        if loc.file:
            parts.append(f"file:{loc.file}")
            source_fields.append("location.file")
        if loc.container_image:
            parts.append(f"img:{loc.container_image}")
            source_fields.append("location.container_image")

        raw_path = loc.path or (loc.url.split("?")[0] if loc.url else None)
        canonical_path = None
        if raw_path:
            canonical_path = re.sub(r"/\d+(?=/|$)", "/{id}", raw_path.split("?")[0].strip()).lower()

        structured = {
            "asset_name": asset.asset_name,
            "host": loc.host,
            "protocol": loc.protocol,
            "port": loc.port,
            "canonical_path": canonical_path,
            "parameter": loc.parameter,
            "parameter_class": loc.parameter_class,
            "package": loc.package,
            "file": loc.file,
        }

        if not parts:
            return SingleView(
                text=None,
                structured=structured,
                source_fields=source_fields,
                extraction_method="missing",
                confidence=0.0,
                status=ViewStatus.MISSING,
                warnings=["No location fields populated."]
            )

        loc_text = " ".join(parts)
        text_redacted = redact_secrets(loc_text)

        if (loc.host or loc.url) and (loc.path or loc.url):
            status = ViewStatus.AVAILABLE
            confidence = 1.0
        elif loc.package and loc.installed_version:
            status = ViewStatus.AVAILABLE
            confidence = 0.9
        elif loc.path:
            status = ViewStatus.PARTIAL
            confidence = 0.7
        elif loc.package:
            status = ViewStatus.PARTIAL
            confidence = 0.6
        elif asset.asset_name:
            status = ViewStatus.PARTIAL
            confidence = 0.4
        else:
            status = ViewStatus.MISSING
            confidence = 0.0

        return SingleView(
            text=text_redacted,
            structured=structured,
            source_fields=source_fields,
            extraction_method="structured_fields",
            confidence=confidence,
            status=status,
            warnings=[]
        )

    def extract_reproduction_view(self, finding: NormalizedFinding) -> SingleView:
        ev = finding.evidence
        source_fields = []

        if ev.request:
            source_fields.append("evidence.request")
        if ev.response:
            source_fields.append("evidence.response")
        if ev.payload:
            source_fields.append("evidence.payload")
        if ev.raw_output:
            source_fields.append("evidence.raw_output")
        if ev.summary:
            source_fields.append("evidence.summary")
        if ev.code_snippet:
            source_fields.append("evidence.code_snippet")

        method = None
        endpoint = None
        if ev.request:
            first_line = ev.request.strip().split("\n")[0]
            req_match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)", first_line, re.IGNORECASE)
            if req_match:
                method = req_match.group(1).upper()
                endpoint = req_match.group(2)

        structured = {
            "method": method,
            "endpoint": endpoint,
            "parameter": finding.location.parameter,
            "payload": ev.payload,
            "has_request": bool(ev.request),
            "has_response": bool(ev.response),
        }

        if not source_fields:
            return SingleView(
                text=None,
                structured=structured,
                source_fields=source_fields,
                extraction_method="missing",
                confidence=0.0,
                status=ViewStatus.MISSING,
                warnings=["No evidence fields present."]
            )

        text_parts = []
        if ev.request:
            payload_str = f" with payload: {ev.payload[:100]}" if ev.payload else ""
            param_str = f" parameter '{finding.location.parameter}'" if finding.location.parameter else ""
            text_parts.append(f"Request: {method or 'REQ'} {endpoint or ''}{param_str}{payload_str}".strip())
        elif ev.payload:
            text_parts.append(f"Payload: {ev.payload[:150]}")

        if ev.summary:
            text_parts.append(f"Summary: {ev.summary}")
        elif ev.raw_output:
            text_parts.append(f"Raw Output: {ev.raw_output[:300]}")
        elif ev.code_snippet:
            text_parts.append(f"Code Snippet: {ev.code_snippet[:200]}")

        repro_text = " ".join(text_parts)
        text_redacted = redact_secrets(repro_text)

        if ev.request and ev.response:
            status = ViewStatus.AVAILABLE
            confidence = 0.95
        elif ev.request:
            status = ViewStatus.AVAILABLE
            confidence = 0.85
        elif ev.raw_output or ev.summary:
            status = ViewStatus.PARTIAL
            confidence = 0.65
        elif ev.code_snippet:
            status = ViewStatus.PARTIAL
            confidence = 0.50
        else:
            status = ViewStatus.MISSING
            confidence = 0.0

        return SingleView(
            text=text_redacted,
            structured=structured,
            source_fields=source_fields,
            extraction_method="structured_fields",
            confidence=confidence,
            status=status,
            warnings=[]
        )

    def extract_impact_view(self, finding: NormalizedFinding) -> SingleView:
        vuln = finding.vulnerability
        source_fields = []
        impact_types = []
        source = "missing"

        # 1. CVSS Vector impact
        if vuln.cvss_vector:
            source_fields.append("vulnerability.cvss_vector")
            vec = vuln.cvss_vector.upper()
            if "C:H" in vec:
                impact_types.append("potential high confidentiality impact")
            if "I:H" in vec:
                impact_types.append("potential high integrity impact")
            if "A:H" in vec:
                impact_types.append("potential high availability impact")
            if impact_types:
                source = "cvss_vector"

        # 2. CWE Map lookup
        if not impact_types and vuln.cwe_primary:
            source_fields.append("vulnerability.cwe_primary")
            if vuln.cwe_primary in CWE_IMPACT_MAP:
                impact_types.extend(CWE_IMPACT_MAP[vuln.cwe_primary])
                source = "cwe_map"

        # 3. Keyword inference
        if not impact_types and (vuln.title or vuln.description):
            combined_text = f"{vuln.title or ''} {vuln.description or ''}".lower()
            source_fields.extend(["vulnerability.title", "vulnerability.description"])
            
            if "authentication bypass" in combined_text or "auth bypass" in combined_text:
                impact_types.append("potential authentication bypass")
            if "remote code execution" in combined_text or "rce" in combined_text:
                impact_types.append("potential remote code execution")
            if "data exfiltration" in combined_text or "data leak" in combined_text or "information disclosure" in combined_text:
                impact_types.append("potential sensitive data exposure")
            if "denial of service" in combined_text or "dos" in combined_text:
                impact_types.append("potential service disruption")
            if "privilege escalation" in combined_text:
                impact_types.append("potential privilege escalation")
            if impact_types:
                source = "keyword_inference"

        structured = {
            "impact_types": impact_types,
            "impact_source": source,
            "confirmed": False
        }

        if not impact_types:
            return SingleView(
                text=None,
                structured=structured,
                source_fields=source_fields,
                extraction_method="missing",
                confidence=0.0,
                status=ViewStatus.MISSING,
                warnings=["Could not infer impact from CVSS, CWE, or keywords."]
            )

        impact_text = f"Potential impact: {'; '.join(impact_types)}"
        text_redacted = redact_secrets(impact_text)

        if source == "cvss_vector":
            status = ViewStatus.AVAILABLE
            confidence = 0.9
        elif source == "cwe_map":
            status = ViewStatus.INFERRED
            confidence = 0.75
        elif source == "keyword_inference":
            status = ViewStatus.INFERRED
            confidence = 0.5
        else:
            status = ViewStatus.MISSING
            confidence = 0.0

        return SingleView(
            text=text_redacted,
            structured=structured,
            source_fields=source_fields,
            extraction_method="cwe_map" if source == "cwe_map" else ("keyword_inference" if source == "keyword_inference" else "structured_fields"),
            confidence=confidence,
            status=status,
            warnings=[]
        )

    def extract_views(self, finding: NormalizedFinding) -> FindingViews:
        desc_view = self.extract_description_view(finding)
        loc_view = self.extract_location_view(finding)
        repro_view = self.extract_reproduction_view(finding)
        impact_view = self.extract_impact_view(finding)

        missing_views = []
        if desc_view.status == ViewStatus.MISSING:
            missing_views.append("description")
        if loc_view.status == ViewStatus.MISSING:
            missing_views.append("location")
        if repro_view.status == ViewStatus.MISSING:
            missing_views.append("reproduction")
        if impact_view.status == ViewStatus.MISSING:
            missing_views.append("impact")

        embedding_text = {}
        if desc_view.text:
            embedding_text["description"] = desc_view.text
        if loc_view.text:
            embedding_text["location"] = loc_view.text
        if repro_view.text:
            embedding_text["reproduction"] = repro_view.text
        if impact_view.text:
            embedding_text["impact"] = impact_view.text

        quality = ViewQuality(
            available_views=4 - len(missing_views),
            missing_views=missing_views,
            warnings=[]
        )

        return FindingViews(
            finding_id=finding.finding_id,
            description=desc_view,
            location=loc_view,
            reproduction=repro_view,
            impact=impact_view,
            embedding_text=embedding_text,
            view_quality=quality,
            extracted_at=datetime.now(timezone.utc)
        )


extractor_service = MultiViewExtractor()
