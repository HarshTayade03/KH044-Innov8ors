"""Contracts for assembled cases and human review decisions."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class CaseStatus(str, Enum):
	PENDING_REVIEW = "pending_review"
	APPROVED = "approved"
	REJECTED = "rejected"
	MORE_EVIDENCE_REQUESTED = "more_evidence_requested"


class ReviewActionType(str, Enum):
	APPROVED = "approved"
	REJECTED = "rejected"
	REQUESTED_EVIDENCE = "requested_evidence"
	PRIORITY_OVERRIDE = "priority_override"


class Case(BaseModel):
	case_id: str
	canonical_issue_id: str
	status: CaseStatus = CaseStatus.PENDING_REVIEW
	title: str
	summary: Optional[str] = None
	case_data: dict[str, Any] = Field(default_factory=dict)
	stale: bool = False
	created_at: datetime
	last_updated_at: datetime
	updated_at: datetime


class ReviewAction(BaseModel):
	actor_id: str = Field(min_length=1, max_length=120)
	reason: str = Field(min_length=1, max_length=4000)
	comment: Optional[str] = Field(default=None, max_length=4000)
	new_tier: Optional[str] = None

	@field_validator("actor_id", "reason")
	@classmethod
	def reject_blank(cls, value: str) -> str:
		value = value.strip()
		if not value:
			raise ValueError("must not be blank")
		return value


class ReviewRecord(BaseModel):
	review_id: str
	case_id: str
	action: ReviewActionType
	actor_id: str
	comment: Optional[str] = None
	reason: Optional[str] = None
	previous_status: Optional[CaseStatus] = None
	new_status: Optional[CaseStatus] = None
	reviewed_at: datetime


class AuditEvent(BaseModel):
	event_id: str
	entity_type: str
	entity_id: str
	action: str
	actor: str
	details: dict[str, Any] = Field(default_factory=dict)
	occurred_at: datetime


class CaseDetail(Case):
	reviews: list[ReviewRecord] = Field(default_factory=list)
	audit_events: list[AuditEvent] = Field(default_factory=list)

