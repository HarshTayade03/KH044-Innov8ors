"""
api/cases.py — Case generation, prioritization, and human review endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status
from src.app.repositories.risk_repo import risk_repo
from src.app.services.risk_engine import risk_engine
from src.app.services.threat_intel import ThreatIntelUnavailable
from src.app.services.case_service import case_service
from src.app.repositories.case_repo import case_repo
from src.app.schemas.case import Case, CaseStatus, ReviewDecision, ReviewAction

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

@router.post("/canonical-issues/{canonical_issue_id}/generate-case", response_model=Case)
async def generate_case(canonical_issue_id: str):
    try: return case_service.assemble(canonical_issue_id)
    except LookupError as e: raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e: raise HTTPException(status_code=409, detail=str(e))


@router.get("/cases", response_model=list[Case])
async def list_cases(status: CaseStatus | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    return case_repo.list(status.value if status else None, limit, offset)


@router.get("/cases/{case_id}")
async def get_case(case_id: str):
    case = case_repo.get(case_id)
    if not case: raise HTTPException(status_code=404, detail="Case not found")
    return {
        "case": case.model_dump(),
        "reviews": [review.model_dump() for review in case_repo.reviews(case_id)],
        "audit": [event.model_dump() for event in case_repo.audits(case_id)],
    }


@router.post("/cases/{case_id}/approve", response_model=Case)
async def approve_case(case_id: str, decision: ReviewDecision):
    return _review(case_id, ReviewAction.APPROVE, decision)


@router.post("/cases/{case_id}/reject", response_model=Case)
async def reject_case(case_id: str, decision: ReviewDecision):
    return _review(case_id, ReviewAction.REJECT, decision)


@router.post("/cases/{case_id}/request-evidence", response_model=Case)
async def request_evidence(case_id: str, decision: ReviewDecision):
    return _review(case_id, ReviewAction.REQUEST_EVIDENCE, decision)


@router.post("/cases/{case_id}/override-priority", response_model=Case)
async def override_priority(case_id: str, decision: ReviewDecision):
    return _review(case_id, ReviewAction.PRIORITY_OVERRIDE, decision)

def _review(case_id, action, decision):
    try: return case_service.review(case_id, action, decision)
    except LookupError as e: raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e: raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e: raise HTTPException(status_code=409, detail=str(e))
