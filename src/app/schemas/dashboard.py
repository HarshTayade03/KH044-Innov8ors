"""Dashboard summary contracts exposed to the analyst console."""

from typing import Any

from pydantic import BaseModel, Field


class DashboardMetrics(BaseModel):
    """Counts and distributions used by the dashboard without placeholder data."""

    findings: int = Field(ge=0)
    active_issues: int = Field(ge=0)
    clusters: int = Field(ge=0)
    validations: int = Field(ge=0)
    cases: int = Field(ge=0)
    prioritized: int = Field(ge=0)
    validation_statuses: dict[str, int] = Field(default_factory=dict)
    remediation_tiers: dict[str, int] = Field(default_factory=dict)
    case_statuses: dict[str, int] = Field(default_factory=dict)
    evidence_artifacts: int = Field(ge=0)
    provenance: dict[str, Any] = Field(default_factory=dict)
