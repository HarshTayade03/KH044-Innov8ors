"""Contracts for generated cases and analyst review."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import AliasChoices, BaseModel, Field


class CaseStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    MORE_EVIDENCE_REQUESTED = "more_evidence_requested"


class ReviewDecision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    EVIDENCE_REQUESTED = "requested_evidence"
    PRIORITY_OVERRIDE = "priority_override"


class ReviewAction(BaseModel):
    actor_id: str = Field(min_length=1, validation_alias=AliasChoices("actor_id", "actor"))
    reason: str = Field(min_length=1)
    priority: dict[str, Any] | None = None


class Review(BaseModel):
    review_id: str
    case_id: str
    action: str
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


class Case(BaseModel):
    case_id: str
    canonical_issue_id: str
    status: CaseStatus = CaseStatus.PENDING_REVIEW
    stale: bool = False
    title: str
    summary: str | None = None
    case_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    last_updated_at: datetime
    reviews: list[Review] = Field(default_factory=list)
    audit_events: list[AuditEvent] = Field(default_factory=list)
