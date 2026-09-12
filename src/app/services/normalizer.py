"""
services/normalizer.py — Normalization service orchestrating parser -> validation -> canonical schema -> DB.

Defined according to docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

# Register built-in parsers during application import, not as a side effect of test imports.
from src.app.parsers import burp, nessus, sarif, snyk, trivy  # noqa: F401

from src.app.parsers.base import (
    get_parser,
    normalize_cve,
    normalize_cwe,
    normalize_severity,
    derive_cvss_from_severity,
    infer_parameter_class,
    compute_fingerprint,
    compute_completeness,
)
from src.app.schemas.canonical import (
    NormalizedFinding,
    SourceInfo,
    VulnerabilityInfo,
    AssetInfo,
    LocationInfo,
    EvidenceInfo,
    RemediationInfo,
    ProvenanceInfo,
    QualityInfo,
    BatchSummary,
    RejectedRecordDetail,
    ManualFindingCreate,
)
from src.app.repositories.findings_repo import repo


def hash_raw_record(record: dict[str, Any]) -> str:
    """SHA-256 hash of deterministic JSON string representation."""
    serialized = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class NormalizerService:
    """Orchestrates parsing, field normalization, fingerprint calculation, and database persistence."""

    def normalize_record(
        self,
        raw_record: dict[str, Any],
        source_scanner: str,
        ingestion_batch_id: str,
        source_file: Optional[str] = None,
        parser_key: Optional[str] = None,
    ) -> NormalizedFinding:
        """
        Normalize a single raw scanner record into a canonical NormalizedFinding.
        """
        finding_id = f"f-{uuid.uuid4()}"
        now_dt = datetime.now(timezone.utc)
        raw_hash = hash_raw_record(raw_record)

        warnings: list[str] = []
        errors: list[str] = []

        parser = get_parser(parser_key or source_scanner)
        parser_name = parser.__class__.__name__ if parser else "GenericParser"

        if parser:
            parsed = parser.parse(raw_record)
        else:
            warnings.append(f"No specific parser found for scanner '{source_scanner}'. Used generic mapping.")
            parsed = raw_record

        # Extract & Normalize Vulnerability Info
        title = parsed.get("title") or raw_record.get("title") or raw_record.get("name") or "Untitled Vulnerability"
        if not title or title == "Untitled Vulnerability":
            warnings.append("Missing explicit vulnerability title.")

        raw_cves = parsed.get("cve_ids") or []
        norm_cves = [nc for nc in (normalize_cve(c) for c in raw_cves) if nc]

        raw_cwes = parsed.get("cwe_ids") or []
        norm_cwes = [nc for nc in (normalize_cwe(c) for c in raw_cwes) if nc]
        cwe_primary = norm_cwes[0] if norm_cwes else None

        sev_raw = parsed.get("severity_raw") or raw_record.get("severity")
        severity, sev_source = normalize_severity(sev_raw)
        if severity == "Unknown":
            warnings.append(f"Could not reliably map raw severity '{sev_raw}'. Assigned 'Unknown'.")

        cvss_score = parsed.get("cvss_score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
                sev_confidence = 1.0
            except (ValueError, TypeError):
                cvss_score = None
                sev_confidence = 0.5
        else:
            cvss_score, sev_confidence = derive_cvss_from_severity(severity)
            if severity != "Unknown":
                sev_source = "derived"
                warnings.append(f"CVSS score derived from qualitative severity '{severity}'.")

        vuln_info = VulnerabilityInfo(
            title=title,
            description=parsed.get("description"),
            cve_ids=norm_cves,
            cwe_ids=norm_cwes,
            cwe_primary=cwe_primary,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=parsed.get("cvss_vector"),
            cvss_version=parsed.get("cvss_version"),
            severity_source=sev_source,
            severity_confidence=sev_confidence,
        )

        # Extract & Normalize Location Info
        url = parsed.get("url")
        path = parsed.get("path")
        host = parsed.get("host")
        parameter = parsed.get("parameter")
        param_class = infer_parameter_class(parameter)

        loc_info = LocationInfo(
            host=host,
            port=parsed.get("port"),
            protocol=parsed.get("protocol"),
            url=url,
            path=path,
            parameter=parameter,
            parameter_class=param_class,
            file=parsed.get("file"),
            package=parsed.get("package"),
            installed_version=parsed.get("installed_version"),
            fixed_version=parsed.get("fixed_version"),
            container_image=parsed.get("container_image"),
            function=parsed.get("function"),
        )

        # Compute Fingerprint
        url_or_path = url or path or loc_info.package or loc_info.file or loc_info.host
        fingerprint = compute_fingerprint(cwe_primary, url_or_path, param_class)

        # Asset Info
        asset_name = parsed.get("asset_name") or host or loc_info.container_image or loc_info.package or "unknown_asset"
        asset_type = parsed.get("asset_type") or "unknown"
        asset_info = AssetInfo(
            asset_name=asset_name,
            asset_type=asset_type,
            environment="lab",
            internet_facing=False,
            criticality="medium",
        )

        # Source Info
        source_info = SourceInfo(
            tool_name=source_scanner,
            tool_version=parsed.get("tool_version"),
            original_severity_raw=str(sev_raw) if sev_raw is not None else None,
            original_severity_vocab="qualitative" if sev_source == "derived" else "cvss",
            original_cvss_score=parsed.get("cvss_score"),
            original_confidence=str(parsed.get("confidence")) if parsed.get("confidence") else None,
        )

        # Evidence Info
        evidence_info = EvidenceInfo(
            summary=parsed.get("evidence_summary"),
            request=parsed.get("request"),
            response=parsed.get("response"),
            payload=parsed.get("payload"),
            raw_output=parsed.get("raw_output"),
            code_snippet=parsed.get("code_snippet"),
        )

        # Remediation Info
        remediation_info = RemediationInfo(
            recommendation=parsed.get("solution") or parsed.get("recommendation"),
            fixed_version=parsed.get("fixed_version"),
            reference_urls=parsed.get("reference_urls", []),
        )

        # Provenance Info
        provenance_info = ProvenanceInfo(
            source_file=source_file,
            parser_name=parser_name,
            parser_version="1.0.0",
            raw_record_hash=raw_hash,
            original_data=raw_record,
        )

        # Quality Info
        status = "normalized_with_warnings" if warnings else "normalized"
        if errors:
            status = "rejected"

        temp_dict = {
            "vulnerability": vuln_info.model_dump(),
            "asset": asset_info.model_dump(),
            "location": loc_info.model_dump(),
            "evidence": evidence_info.model_dump(),
            "provenance": provenance_info.model_dump(),
        }
        completeness = compute_completeness(temp_dict)

        quality_info = QualityInfo(
            normalization_status=status,
            completeness_score=completeness,
            warnings=warnings,
            errors=errors,
        )

        finding = NormalizedFinding(
            finding_id=finding_id,
            fingerprint=fingerprint,
            source_scanner=source_scanner,
            source_finding_id=parsed.get("source_finding_id"),
            ingestion_batch_id=ingestion_batch_id,
            ingested_at=now_dt,
            source=source_info,
            vulnerability=vuln_info,
            asset=asset_info,
            location=loc_info,
            evidence=evidence_info,
            remediation=remediation_info,
            provenance=provenance_info,
            quality=quality_info,
        )

        # Persist raw + normalized records to DB
        repo.save_scanner_finding(
            finding_id=finding_id,
            source_scanner=source_scanner,
            source_finding_id=finding.source_finding_id,
            ingestion_batch_id=ingestion_batch_id,
            raw_data=raw_record,
            raw_data_hash=raw_hash,
            status=status,
        )
        repo.save_normalized_finding(finding)

        return finding

    def normalize_batch(
        self,
        records: list[dict[str, Any]],
        source_scanner: str,
        source_file: Optional[str] = None,
    ) -> BatchSummary:
        """
        Normalize a list of raw records into canonical findings and persist all of them.
        Isolates failures so 1 bad record does not abort the batch.
        """
        batch_id = f"batch-{uuid.uuid4()}"
        norm_count = 0
        warn_count = 0
        rej_count = 0
        rejected_details = []

        for idx, record in enumerate(records):
            try:
                finding = self.normalize_record(
                    raw_record=record,
                    source_scanner=source_scanner,
                    ingestion_batch_id=batch_id,
                    source_file=source_file,
                )
                if finding.quality.normalization_status == "normalized":
                    norm_count += 1
                elif finding.quality.normalization_status == "normalized_with_warnings":
                    warn_count += 1
                else:
                    rej_count += 1
                    rejected_details.append(
                        RejectedRecordDetail(index=idx, reason="; ".join(finding.quality.errors) or "Unknown error")
                    )
            except Exception as e:
                rej_count += 1
                rejected_details.append(RejectedRecordDetail(index=idx, reason=str(e)))

        return BatchSummary(
            batch_id=batch_id,
            source_scanner=source_scanner,
            total_received=len(records),
            normalized=norm_count,
            normalized_with_warnings=warn_count,
            rejected=rej_count,
            rejected_details=rejected_details,
            status="completed",
            next_stage="multi_view_extraction",
        )

    def normalize_manual_entry(self, entry: ManualFindingCreate) -> NormalizedFinding:
        """
        Normalize a manual entry payload into a canonical finding.
        """
        raw_record = entry.model_dump()
        batch_id = f"batch-manual-{uuid.uuid4()}"

        # Adapt manual entry dict to common parser format
        parsed_record = {
            "title": entry.title,
            "description": entry.description,
            "severity_raw": entry.severity,
            "cvss_score": entry.cvss_score,
            "cve_ids": entry.cve_ids,
            "cwe_ids": entry.cwe_ids,
            "asset_name": entry.asset_name,
            "url": entry.url,
            "parameter": entry.parameter,
            "request": entry.request,
            "response": entry.response,
            "evidence_summary": entry.notes,
        }

        return self.normalize_record(
            raw_record=parsed_record,
            source_scanner=entry.scanner_name.lower().replace(" ", "_"),
            ingestion_batch_id=batch_id,
            source_file="manual_entry_form",
        )


normalizer_service = NormalizerService()
