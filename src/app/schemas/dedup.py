"""
schemas/dedup.py — Deduplication schemas for Stage A (fingerprint) and Stage B (semantic).

Defined according to docs/MODULE_SPECS/M3_deduplication.md.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field


class ClusterMethod(str, Enum):
    FINGERPRINT = "fingerprint"
    SEMANTIC = "semantic"
    MANUAL = "manual"


class ClusterStatus(str, Enum):
    CANDIDATE = "candidate"
    MERGED = "merged"
    KEPT_SEPARATE = "kept_separate"
    REJECTED_MERGE = "rejected_merge"
    UNCERTAIN = "uncertain"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    MERGED = "merged"
    KEPT_SEPARATE = "kept_separate"
    REJECTED_MERGE = "rejected_merge"


class ClusterMember(BaseModel):
    id: str
    cluster_id: str
    finding_id: str
    role: str = "secondary"  # primary | secondary
    joined_at: datetime


class Cluster(BaseModel):
    cluster_id: str
    cluster_method: ClusterMethod
    status: ClusterStatus = ClusterStatus.CANDIDATE
    similarity_score: Optional[float] = None
    merge_reason: list[str] = Field(default_factory=list)
    merge_confidence: Optional[float] = 1.0
    hdbscan_params: Optional[dict[str, Any]] = None
    members: list[ClusterMember] = Field(default_factory=list)
    run_at: datetime
    created_at: datetime
    updated_at: datetime


class CanonicalIssue(BaseModel):
    canonical_issue_id: str
    title: str
    cluster_id: Optional[str] = None
    source_finding_ids: list[str] = Field(default_factory=list)
    source_scanners: list[str] = Field(default_factory=list)
    merge_method: ClusterMethod
    merge_confidence: float = 1.0
    merge_reason: list[str] = Field(default_factory=list)
    review_status: ReviewStatus = ReviewStatus.PENDING
    created_at: datetime
    updated_at: datetime


class DedupRunSummary(BaseModel):
    run_id: str
    total_findings_processed: int
    deterministic_clusters_created: int
    semantic_clusters_created: int
    total_canonical_issues: int
    run_at: datetime
