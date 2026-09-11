"""
api/findings.py — Normalized finding query & view extraction / embedding endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status

from src.app.schemas.canonical import NormalizedFinding
from src.app.repositories.findings_repo import repo
from src.app.services.extractor import extractor_service
from src.app.services.embedding import embedding_service

router = APIRouter(tags=["Findings"])


@router.get("/findings", response_model=dict)
async def list_findings(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    List all normalized findings in the system with pagination.
    """
    findings = repo.list_normalized_findings(limit=limit, offset=offset)
    total = repo.count_normalized_findings()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": [f.model_dump() for f in findings],
    }


@router.get("/findings/{finding_id}", response_model=dict)
async def get_finding(finding_id: str):
    """
    Retrieve a single canonical NormalizedFinding by its ID.
    """
    finding = repo.get_normalized_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Normalized finding with ID '{finding_id}' not found.",
        )
    return finding.model_dump()


@router.post("/findings/{finding_id}/extract-views", response_model=dict)
async def extract_finding_views(finding_id: str):
    """
    Trigger 4-view extraction for a single normalized finding and persist to DB.
    """
    finding = repo.get_normalized_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Normalized finding with ID '{finding_id}' not found.",
        )
    views = extractor_service.extract_views(finding)
    repo.save_finding_views(views)
    return views.model_dump()


@router.get("/findings/{finding_id}/views", response_model=dict)
async def get_finding_views(finding_id: str):
    """
    Retrieve already-extracted 4-view representation for a finding.
    """
    views = repo.get_finding_views(finding_id)
    if not views:
        # Check if finding exists
        finding = repo.get_normalized_finding(finding_id)
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding with ID '{finding_id}' not found.",
            )
        # Extract on demand if not found
        views = extractor_service.extract_views(finding)
        repo.save_finding_views(views)
    return views.model_dump()


@router.post("/batches/{batch_id}/extract-views", response_model=dict)
async def extract_batch_views(batch_id: str):
    """
    Extract views for all findings in a specific ingestion batch.
    """
    all_findings = repo.list_normalized_findings(limit=1000)
    batch_findings = [f for f in all_findings if f.ingestion_batch_id == batch_id]
    if not batch_findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No findings found for batch '{batch_id}'.",
        )

    completed = 0
    failed = 0
    failed_ids = []

    for finding in batch_findings:
        try:
            views = extractor_service.extract_views(finding)
            repo.save_finding_views(views)
            completed += 1
        except Exception as e:
            failed += 1
            failed_ids.append(finding.finding_id)

    return {
        "batch_id": batch_id,
        "total": len(batch_findings),
        "completed": completed,
        "failed": failed,
        "failed_ids": failed_ids,
    }


@router.post("/findings/{finding_id}/generate-embeddings", response_model=dict)
async def generate_finding_embeddings(finding_id: str):
    """
    Generate vector embeddings for each view and combined embedding for a finding.
    """
    views = repo.get_finding_views(finding_id)
    if not views:
        finding = repo.get_normalized_finding(finding_id)
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding with ID '{finding_id}' not found.",
            )
        views = extractor_service.extract_views(finding)
        repo.save_finding_views(views)

    embeddings = embedding_service.generate_embeddings(views)
    repo.save_finding_embeddings(embeddings)
    return embeddings.model_dump()


@router.get("/findings/{finding_id}/embeddings", response_model=dict)
async def get_finding_embeddings(finding_id: str):
    """
    Retrieve generated embeddings for a finding.
    """
    embeddings = repo.get_finding_embeddings(finding_id)
    if not embeddings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Embeddings for finding '{finding_id}' not found.",
        )
    return embeddings.model_dump()


@router.post("/batches/{batch_id}/generate-embeddings", response_model=dict)
async def generate_batch_embeddings(batch_id: str):
    """
    Generate vector embeddings for all findings in a batch using high-performance batching.
    """
    all_findings = repo.list_normalized_findings(limit=1000)
    batch_findings = [f for f in all_findings if f.ingestion_batch_id == batch_id]
    if not batch_findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No findings found for batch '{batch_id}'.",
        )

    views_list = []
    for f in batch_findings:
        v = repo.get_finding_views(f.finding_id)
        if not v:
            v = extractor_service.extract_views(f)
            repo.save_finding_views(v)
        views_list.append(v)

    embeddings_list = embedding_service.generate_batch_embeddings(views_list)
    for emb in embeddings_list:
        repo.save_finding_embeddings(emb)

    return {
        "batch_id": batch_id,
        "total": len(batch_findings),
        "embedded": len(embeddings_list),
        "status": "completed",
    }
