"""
schemas/risk.py — Risk scoring and threat intelligence schemas.

Defined according to docs/MODULE_SPECS/R0_baseline.md.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field


class RemediationTier(str, Enum):
    IMMEDIATE = "Immediate"
    ACCELERATED = "Accelerated"
    STANDARD = "Standard"


class ThreatEnrichment(BaseModel):
    cve_id: str
    kev_flag: bool = False
    kev_date_added: Optional[str] = None
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    epss_percentile: float = Field(default=0.0, ge=0.0, le=1.0)
    data_source: str = "mock"
    source_fingerprint: Optional[str] = None
    fetched_at: Optional[datetime] = None


class ThreatFeedStatus(BaseModel):
    name: str
    provider: str
    endpoint: str
    mode: str
    available: bool
    last_checked_at: Optional[datetime] = None
    source_fingerprint: Optional[str] = None
    note: str


class RiskFactors(BaseModel):
    cvss_score: float = 0.0
    epss_score: float = 0.0
    kev_flag: bool = False
    asset_criticality: str = "medium"
    internet_facing: bool = False
    sandbox_validated: bool = False


class PriorityResult(BaseModel):
    priority_id: str
    canonical_issue_id: str
    risk_score: float
    remediation_tier: RemediationTier
    factors: dict[str, Any] = Field(default_factory=dict)
    weights_used: dict[str, float] = Field(default_factory=dict)
    explanation: list[str] = Field(default_factory=list)
    calculation_version: str = "risk-model-1.0"
    calculated_at: datetime


class LLMContext(BaseModel):
    """Bounded, display-safe contextual synthesis from an optional provider."""

    exploitability_assessment: str = Field(min_length=1, max_length=1200)
    business_impact_analysis: str = Field(min_length=1, max_length=1200)
    remediation_guidance: str = Field(min_length=1, max_length=1600)
    evidence_basis: list[str] = Field(default_factory=list, max_length=8)
    uncertainty: list[str] = Field(default_factory=list, max_length=8)
    confidence_score: float = Field(ge=0.0, le=1.0)
    provider_used: str = Field(min_length=1, max_length=80)
    model_used: str = Field(min_length=1, max_length=120)
