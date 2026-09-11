"""
api/findings.py — Normalized finding query endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status

from src.app.schemas.canonical import NormalizedFinding
from src.app.repositories.findings_repo import repo

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
