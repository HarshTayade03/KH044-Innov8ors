"""
api/cases.py — Case generation, prioritization, and human review endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status
from src.app.repositories.risk_repo import risk_repo
from src.app.services.risk_engine import risk_engine
from src.app.services.threat_intel import ThreatIntelUnavailable

router = APIRouter(tags=["Cases & Prioritization"])


@router.post("/canonical-issues/{canonical_issue_id}/prioritize", response_model=dict)
async def prioritize_issue(canonical_issue_id: str):
    """
    Calculate composite risk score (0-100), threat enrichment, and remediation tier for a canonical issue.
    """
    try:
        priority = risk_engine.calculate_priority(canonical_issue_id)
        return priority.model_dump()
    except ThreatIntelUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.get("/priorities", response_model=dict)
async def list_priorities(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    List calculated priority scores ordered by risk score descending.
    """
    priorities = risk_repo.list_priorities(limit=limit, offset=offset)
    return {
        "total": len(priorities),
        "limit": limit,
        "offset": offset,
        "priorities": [p.model_dump() for p in priorities],
    }


@router.get("/priorities/{canonical_issue_id}", response_model=dict)
async def get_priority(canonical_issue_id: str):
    """
    Get priority result for a specific canonical issue.
    """
    priority = risk_repo.get_priority_by_issue(canonical_issue_id)
    if not priority:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Priority for canonical issue '{canonical_issue_id}' not found.",
        )
    return priority.model_dump()


# ── Case & Review endpoints (Module 6 stubs) ──────────────────────────────────

@router.post("/canonical-issues/{canonical_issue_id}/generate-case", status_code=501)
async def generate_case(canonical_issue_id: str):
    return {"status": "not_implemented", "module": "M6-05"}


@router.get("/cases", status_code=501)
async def list_cases():
    return {"status": "not_implemented", "module": "M6-05"}


@router.get("/cases/{case_id}", status_code=501)
async def get_case(case_id: str):
    return {"status": "not_implemented", "module": "M6-05"}


@router.post("/cases/{case_id}/approve", status_code=501)
async def approve_case(case_id: str):
    return {"status": "not_implemented", "module": "M6-05"}


@router.post("/cases/{case_id}/reject", status_code=501)
async def reject_case(case_id: str):
    return {"status": "not_implemented", "module": "M6-05"}


@router.post("/cases/{case_id}/request-evidence", status_code=501)
async def request_evidence(case_id: str):
    return {"status": "not_implemented", "module": "M6-05"}


@router.post("/cases/{case_id}/override-priority", status_code=501)
async def override_priority(case_id: str):
    return {"status": "not_implemented", "module": "M6-05"}
