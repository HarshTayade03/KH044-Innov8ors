"""
api/clusters.py — Deduplication cluster and canonical issue endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status
from src.app.repositories.dedup_repo import dedup_repo
from src.app.services.deduplicator import deduplicator_service
from src.app.schemas.dedup import ClusterStatus, ReviewStatus

router = APIRouter(tags=["Deduplication"])


@router.post("/deduplication/run", response_model=dict)
async def run_deduplication():
    """
    Execute full Stage A (Fingerprint) + Stage B (HDBSCAN Semantic) deduplication pipeline.
    """
    summary = deduplicator_service.run_deduplication()
    return summary.model_dump()


@router.get("/clusters", response_model=dict)
async def list_clusters(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    List all deduplication clusters.
    """
    clusters = dedup_repo.list_clusters(limit=limit, offset=offset)
    return {
        "total": len(clusters),
        "limit": limit,
        "offset": offset,
        "clusters": [c.model_dump() for c in clusters],
    }


@router.get("/clusters/{cluster_id}", response_model=dict)
async def get_cluster(cluster_id: str):
    """
    Retrieve details for a single cluster.
    """
    cluster = dedup_repo.get_cluster(cluster_id)
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cluster with ID '{cluster_id}' not found.",
        )
    return cluster.model_dump()


@router.post("/clusters/{cluster_id}/merge", response_model=dict)
async def merge_cluster(cluster_id: str):
    """
    Analyst action: Confirm merge of a candidate cluster into a canonical issue.
    """
    cluster = dedup_repo.get_cluster(cluster_id)
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cluster with ID '{cluster_id}' not found.",
        )
    cluster.status = ClusterStatus.MERGED
    dedup_repo.save_cluster(cluster)
    return {"status": "success", "cluster_id": cluster_id, "cluster_status": cluster.status.value}


@router.post("/clusters/{cluster_id}/split", response_model=dict)
async def split_cluster(cluster_id: str):
    """
    Analyst action: Reject merge and split cluster into separate canonical issues.
    """
    cluster = dedup_repo.get_cluster(cluster_id)
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cluster with ID '{cluster_id}' not found.",
        )
    cluster.status = ClusterStatus.REJECTED_MERGE
    dedup_repo.save_cluster(cluster)

    # Convert member findings to singleton canonical issues
    from src.app.repositories.findings_repo import repo as findings_repo
    from src.app.schemas.dedup import CanonicalIssue, ClusterMethod
    import uuid
    from datetime import datetime, timezone

    now_dt = datetime.now(timezone.utc)
    new_issues = []
    for member in cluster.members:
        finding = findings_repo.get_normalized_finding(member.finding_id)
        if finding:
            issue = CanonicalIssue(
                canonical_issue_id=f"issue-split-{uuid.uuid4()}",
                title=finding.vulnerability.title,
                cluster_id=None,
                source_finding_ids=[finding.finding_id],
                source_scanners=[finding.source_scanner],
                merge_method=ClusterMethod.MANUAL,
                merge_confidence=1.0,
                merge_reason=["Split manually by analyst from cluster " + cluster_id],
                review_status=ReviewStatus.KEPT_SEPARATE,
                created_at=now_dt,
                updated_at=now_dt,
            )
            dedup_repo.save_canonical_issue(issue)
            new_issues.append(issue.canonical_issue_id)

    return {
        "status": "success",
        "cluster_id": cluster_id,
        "cluster_status": cluster.status.value,
        "new_canonical_issues": new_issues,
    }


@router.get("/canonical-issues", response_model=dict)
async def list_canonical_issues(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    List all canonical issues.
    """
    issues = dedup_repo.list_canonical_issues(limit=limit, offset=offset)
    return {
        "total": len(issues),
        "limit": limit,
        "offset": offset,
        "canonical_issues": [i.model_dump() for i in issues],
    }


@router.get("/canonical-issues/{canonical_issue_id}", response_model=dict)
async def get_canonical_issue(canonical_issue_id: str):
    """
    Retrieve details for a single canonical issue.
    """
    issue = dedup_repo.get_canonical_issue(canonical_issue_id)
    if not issue:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Canonical issue with ID '{canonical_issue_id}' not found.",
        )
    return issue.model_dump()
