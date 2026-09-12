"""Contracts for assembled cases and analyst review."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

class CaseStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EVIDENCE_REQUESTED = "more_evidence_requested"
    RESOLVED = "resolved"

class ReviewAction(str, Enum):
    APPROVE = "approved"
    REJECT = "rejected"
    REQUEST_EVIDENCE = "requested_evidence"
    PRIORITY_OVERRIDE = "priority_override"
    RESOLVE = "resolved"

class Case(BaseModel):
    case_id: str
    canonical_issue_id: str
    status: CaseStatus
    title: str
    summary: str | None = None
    stale: bool = False
    case_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    last_updated_at: datetime

class ReviewDecision(BaseModel):
    actor: str | None = Field(default=None, min_length=1)
    actor_id: str | None = Field(default=None, min_length=1)
    reason: str = Field(min_length=1)

class Review(BaseModel):
    review_id: str
    case_id: str
    action: ReviewAction
    actor_id: str
    reason: str
    previous_status: CaseStatus | None = None
    new_status: CaseStatus | None = None
    reviewed_at: datetime

class AuditEvent(BaseModel):
    event_id: str
    entity_type: str
    entity_id: str
    action: str
    actor: str
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime
