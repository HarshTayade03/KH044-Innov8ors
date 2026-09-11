"""
api/clusters.py — Deduplication cluster and canonical issue endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status
from src.app.repositories.dedup_repo import dedup_repo
from src.app.services.deduplicator import deduplicator_service, DedupConflict

router = APIRouter(tags=["Deduplication"])


@router.post("/deduplication/run", response_model=dict)
async def run_deduplication():
    """
    Execute full Stage A (Fingerprint) + Stage B (HDBSCAN Semantic) deduplication pipeline.
    """
    try:
        return deduplicator_service.run_deduplication().model_dump()
    except DedupConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


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


def review_cluster(cluster_id: str, merge: bool):
    try:
        return deduplicator_service.review_cluster(cluster_id, merge)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DedupConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/clusters/{cluster_id}/merge", response_model=dict)
async def merge_cluster(cluster_id: str):
    return review_cluster(cluster_id, True)


@router.post("/clusters/{cluster_id}/split", response_model=dict)
async def split_cluster(cluster_id: str):
    return review_cluster(cluster_id, False)


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
