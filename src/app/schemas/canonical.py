"""
canonical.py — Canonical NormalizedFinding schema.

Single source of truth for all normalized vulnerability findings.
Defined according to docs/normal.txt and docs/MODULE_SPECS/M1_parsers_normalizer.md.
"""

from datetime import datetime
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field


class SourceInfo(BaseModel):
    tool_name: str
    tool_version: Optional[str] = None
    tool_run_id: Optional[str] = None
    tool_run_at: Optional[datetime] = None
    original_severity_raw: Optional[str] = None
    original_severity_vocab: Literal["cvss", "qualitative", "sarif_level", "unknown"] = "unknown"
    original_cvss_score: Optional[float] = None
    original_cvss_vector: Optional[str] = None
    original_confidence: Optional[str] = None


class VulnerabilityInfo(BaseModel):
    title: str
    description: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cwe_primary: Optional[str] = None
    severity: Literal["Critical", "High", "Medium", "Low", "Informational", "Unknown"] = "Unknown"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    severity_source: Literal["tool", "derived", "analyst_override"] = "tool"
    severity_confidence: float = 1.0


class AssetInfo(BaseModel):
    asset_name: str
    asset_type: Literal["web_application", "api", "host", "container", "library", "unknown"] = "unknown"
    environment: Optional[Literal["prod", "staging", "dev", "lab"]] = "lab"
    internet_facing: bool = False
    criticality: Optional[Literal["critical", "high", "medium", "low", "unknown"]] = "medium"


class LocationInfo(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    parameter: Optional[str] = None
    parameter_class: Optional[Literal["id", "auth", "redirect", "file", "generic"]] = None
    file: Optional[str] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    container_image: Optional[str] = None
    function: Optional[str] = None


class EvidenceInfo(BaseModel):
    summary: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    payload: Optional[str] = None
    raw_output: Optional[str] = None
    code_snippet: Optional[str] = None


class RemediationInfo(BaseModel):
    recommendation: Optional[str] = None
    fixed_version: Optional[str] = None
    reference_urls: list[str] = Field(default_factory=list)


class ProvenanceInfo(BaseModel):
    source_file: Optional[str] = None
    parser_name: str
    parser_version: str = "1.0.0"
    raw_record_hash: str
    original_data: dict[str, Any] = Field(default_factory=dict)


class QualityInfo(BaseModel):
    normalization_status: Literal["normalized", "normalized_with_warnings", "rejected"] = "normalized"
    completeness_score: float = 1.0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class NormalizedFinding(BaseModel):
    finding_id: str
    fingerprint: str
    source_scanner: str
    source_finding_id: Optional[str] = None
    ingestion_batch_id: str
    ingested_at: datetime
    source: SourceInfo
    vulnerability: VulnerabilityInfo
    asset: AssetInfo
    location: LocationInfo
    evidence: EvidenceInfo
    remediation: RemediationInfo
    provenance: ProvenanceInfo
    quality: QualityInfo


# ── Ingestion DTOs ─────────────────────────────────────────────────────────────

class ManualFindingCreate(BaseModel):
    title: str
    description: Optional[str] = None
    scanner_name: str = "Manual Review"
    severity: Literal["Critical", "High", "Medium", "Low", "Informational", "Unknown"] = "Medium"
    asset_name: str
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    url: Optional[str] = None
    parameter: Optional[str] = None
    cvss_score: Optional[float] = None
    request: Optional[str] = None
    response: Optional[str] = None
    notes: Optional[str] = None


class DirectIngestPayload(BaseModel):
    source_scanner: str
    findings: list[dict[str, Any]]


class RejectedRecordDetail(BaseModel):
    index: int
    reason: str


class BatchSummary(BaseModel):
    batch_id: str
    source_scanner: str
    total_received: int
    normalized: int
    normalized_with_warnings: int
    rejected: int
    rejected_details: list[RejectedRecordDetail] = Field(default_factory=list)
    status: str = "completed"
    next_stage: str = "multi_view_extraction"
