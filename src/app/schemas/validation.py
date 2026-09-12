"""Contracts for offline lab validation and immutable evidence."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

class SandboxMode(str, Enum):
    LAB_SIMULATOR = "lab_simulator"
    DOCKER = "docker"

class ValidationStatus(str, Enum):
    SIMULATED_MATCH = "simulated_match"
    SIMULATED_NO_MATCH = "simulated_no_match"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"

class ValidationRequest(BaseModel):
    mode: SandboxMode = SandboxMode.LAB_SIMULATOR
    scenario: str | None = None
    target_host: str | None = None
    simulate_timeout: bool = False

class Artifact(BaseModel):
    artifact_id: str
    validation_id: str
    artifact_type: str
    content: str
    content_hash: str
    content_size: int = Field(ge=0)
    redacted: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

class ValidationResult(BaseModel):
    validation_id: str
    canonical_issue_id: str
    finding_id: str
    status: ValidationStatus
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    sandbox_mode: SandboxMode
    scenario: str
    target_host: str
    execution_summary: str
    limitations: list[str] = Field(default_factory=list)
    executed_at: datetime
    timeout_seconds: int
    artifact_ids: list[str] = Field(default_factory=list)
    created_at: datetime


class ValidationBatchFailure(BaseModel):
    canonical_issue_id: str
    error: str


class ValidationBatchResponse(BaseModel):
    results: list[ValidationResult] = Field(default_factory=list)
    failures: list[ValidationBatchFailure] = Field(default_factory=list)


class EvidenceResponse(BaseModel):
    validation_id: str
    artifacts: list[Artifact]
