"""
schemas/views.py — Multi-View schema definitions.

Defined according to docs/MODULE_SPECS/M2_views_embeddings.md.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field


class ViewStatus(str, Enum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    INFERRED = "inferred"
    MISSING = "missing"
    CONFLICTING = "conflicting"


class SingleView(BaseModel):
    text: Optional[str] = None           # embedding-ready text (redacted of secrets)
    structured: dict[str, Any] = Field(default_factory=dict)
    source_fields: list[str] = Field(default_factory=list)
    extraction_method: str = "structured_fields"
    confidence: float = 1.0
    status: ViewStatus = ViewStatus.AVAILABLE
    warnings: list[str] = Field(default_factory=list)


class ViewQuality(BaseModel):
    available_views: int = 4
    missing_views: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class FindingViews(BaseModel):
    finding_id: str
    description: SingleView
    location: SingleView
    reproduction: SingleView
    impact: SingleView
    embedding_text: dict[str, str] = Field(default_factory=dict)
    view_quality: ViewQuality
    extracted_at: datetime


class FindingEmbeddings(BaseModel):
    finding_id: str
    embedding_model: str
    model_version: Optional[str] = None
    embedding_dimension: int = 384
    embeddings: dict[str, Optional[list[float]]] = Field(default_factory=dict)
    combined_embedding: Optional[list[float]] = None
    generated_at: datetime
    missing_views: list[str] = Field(default_factory=list)
