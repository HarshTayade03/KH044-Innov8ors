"""Contracts for authorized benchmark sources and safe evaluation metadata."""

from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class BenchmarkKind(str, Enum):
    APPLICATION = "application"
    DATASET = "dataset"
    LOCALIZATION = "localization"
    TRIAGE_PIPELINE = "triage_pipeline"


class BenchmarkSource(BaseModel):
    source_id: str
    name: str
    kind: BenchmarkKind
    url: HttpUrl
    purpose: str
    expected_artifact: str
    execution_allowed: bool = False
    authorization_required: bool = True
    provenance_note: str
    license_note: str | None = None


class BenchmarkCatalog(BaseModel):
    sources: list[BenchmarkSource] = Field(default_factory=list)
    safety_policy: str
