"""
api/cases.py — Case generation, prioritization, and human review endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, status
from src.app.repositories.risk_repo import risk_repo
from src.app.services.risk_engine import risk_engine
from src.app.services.threat_intel import ThreatIntelUnavailable
from src.app.schemas.case import CaseStatus, ReviewAction, ReviewActionType
from src.app.services.case_service import CaseConflict, case_service

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


def _case_error(exc):
    if isinstance(exc, LookupError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, CaseConflict):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


@router.post("/canonical-issues/{canonical_issue_id}/generate-case", response_model=dict, status_code=201)
async def generate_case(canonical_issue_id: str):
    try:
        return case_service.generate(canonical_issue_id).model_dump(mode="json")
    except (LookupError, CaseConflict, ValueError) as exc:
        raise _case_error(exc) from exc


@router.get("/cases", response_model=dict)
async def list_cases(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), status_filter: CaseStatus | None = Query(default=None, alias="status")):
    cases = case_service.list_cases(limit, offset, status_filter)
    return {"total": len(cases), "limit": limit, "offset": offset, "cases": [item.model_dump(mode="json") for item in cases]}


@router.get("/cases/{case_id}", response_model=dict)
async def get_case(case_id: str):
    try:
        return case_service.detail(case_id).model_dump(mode="json")
    except LookupError as exc:
        raise _case_error(exc) from exc


@router.post("/cases/{case_id}/approve", response_model=dict)
async def approve_case(case_id: str, action: ReviewAction):
    return _review(case_id, ReviewActionType.APPROVED, action)


@router.post("/cases/{case_id}/reject", response_model=dict)
async def reject_case(case_id: str, action: ReviewAction):
    return _review(case_id, ReviewActionType.REJECTED, action)


@router.post("/cases/{case_id}/request-evidence", response_model=dict)
async def request_evidence(case_id: str, action: ReviewAction):
    return _review(case_id, ReviewActionType.REQUESTED_EVIDENCE, action)


@router.post("/cases/{case_id}/override-priority", response_model=dict)
async def override_priority(case_id: str, action: ReviewAction):
    return _review(case_id, ReviewActionType.PRIORITY_OVERRIDE, action)


def _review(case_id: str, action_type: ReviewActionType, action: ReviewAction):
    try:
        return case_service.review(case_id, action_type, action).model_dump(mode="json")
    except (LookupError, CaseConflict, ValueError) as exc:
        raise _case_error(exc) from exc
