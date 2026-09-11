"""
schemas/risk.py — Risk scoring and threat intelligence schemas.

Defined according to docs/MODULE_SPECS/M4_threat_intel_prioritization.md.
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
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    data_source: str = "mock"


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
