"""
api/clusters.py — Deduplication cluster and canonical issue endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
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


@router.get("/clusters/{cluster_id}/comparison", response_model=dict)
async def compare_cluster_members(cluster_id: str):
    """Return persisted member evidence for side-by-side analyst comparison."""
    cluster = dedup_repo.get_cluster(cluster_id)
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cluster with ID '{cluster_id}' not found.",
        )

    members = []
    for member in cluster.members:
        finding = findings_repo.get_normalized_finding(member.finding_id)
        if not finding:
            continue
        views = findings_repo.get_finding_views(member.finding_id)
        embeddings = findings_repo.get_finding_embeddings(member.finding_id)
        members.append({
            "finding_id": finding.finding_id,
            "role": member.role,
            "source_scanner": finding.source_scanner,
            "title": finding.vulnerability.title,
            "severity": finding.vulnerability.severity,
            "cwe_ids": finding.vulnerability.cwe_ids,
            "location": finding.location.model_dump(mode="json"),
            "views": views.model_dump(mode="json") if views else None,
            "embedding_provenance": {
                "backend": embeddings.embedding_model,
                "version": embeddings.model_version,
                "dimension": embeddings.embedding_dimension,
                "missing_views": embeddings.missing_views,
            } if embeddings else None,
        })
    return {
        "cluster": cluster.model_dump(mode="json"),
        "member_count": len(members),
        "members": members,
    }


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
