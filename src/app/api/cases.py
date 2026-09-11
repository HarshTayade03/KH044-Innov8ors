"""
api/cases.py — Case generation, prioritization, and human review endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status
from src.app.repositories.risk_repo import risk_repo
from src.app.services.risk_engine import risk_engine
from src.app.services.threat_intel import ThreatIntelUnavailable
from src.app.schemas.case import CaseStatus, ReviewAction
from src.app.services.case_service import CaseError, CaseValidationError, case_service

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


# ── Case & Review endpoints ───────────────────────────────────────────────────

@router.post("/canonical-issues/{canonical_issue_id}/generate-case")
async def generate_case(canonical_issue_id: str):
    try:
        return case_service.generate(canonical_issue_id)
    except CaseError as exc:
        message = str(exc)
        raise HTTPException(status_code=409 if ("stale" in message or "reviewed" in message) else 404,
                            detail=message) from exc


@router.get("/cases")
async def list_cases(
    status_filter: CaseStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    cases = case_service.list(status=status_filter, limit=limit, offset=offset)
    return {"total": len(cases), "limit": limit, "offset": offset,
            "cases": [case.model_dump(mode="json") for case in cases]}


@router.get("/cases/{case_id}")
async def get_case(case_id: str):
    try:
        return case_service.get(case_id)
    except CaseError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/cases/{case_id}/approve")
async def approve_case(case_id: str, action: ReviewAction):
    return _review(case_id, "approved", action)


@router.post("/cases/{case_id}/reject")
async def reject_case(case_id: str, action: ReviewAction):
    return _review(case_id, "rejected", action)


@router.post("/cases/{case_id}/request-evidence")
async def request_evidence(case_id: str, action: ReviewAction):
    return _review(case_id, "requested_evidence", action)


@router.post("/cases/{case_id}/override-priority")
async def override_priority(case_id: str, action: ReviewAction):
    return _review(case_id, "priority_override", action)


def _review(case_id: str, kind: str, action: ReviewAction):
    try:
        return case_service.review(case_id, kind, action)
    except CaseError as exc:
        message = str(exc)
        code = 422 if isinstance(exc, CaseValidationError) else (
            409 if ("cannot" in message or "Terminal" in message) else 404
        )
        raise HTTPException(status_code=code, detail=message) from exc
