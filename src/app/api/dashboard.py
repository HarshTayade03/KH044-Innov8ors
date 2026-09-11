"""Read-only analyst dashboard endpoints."""
from fastapi import APIRouter, HTTPException, Query
from src.app.repositories.dashboard_repo import dashboard_repo
from src.app.services.dashboard_service import dashboard_service

router = APIRouter(tags=["Dashboard"])

@router.get("/dashboard/metrics")
async def get_metrics():
    return dashboard_service.metrics()


@router.get("/dashboard/cases")
@router.get("/dashboard/case-queue")
async def case_queue(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
):
    return dashboard_service.queue(limit, offset, status)


@router.get("/dashboard/cases/{case_id}")
async def case_detail(case_id: str):
    result = dashboard_repo.get_case(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return result


@router.get("/dashboard/cases/{case_id}/validation")
async def case_validation(case_id: str):
    result = dashboard_repo.validations(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return {"data_status": "available" if result else "empty", "case_id": case_id, "validations": result}


@router.get("/dashboard/cases/{case_id}/evidence")
async def case_evidence(case_id: str):
    result = dashboard_repo.evidence(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return {"data_status": "available" if result else "empty", "case_id": case_id, "artifacts": result}


@router.get("/dashboard/cases/{case_id}/audit")
async def case_audit(case_id: str):
    result = dashboard_repo.audit(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return {"data_status": "available" if result else "empty", "case_id": case_id, "events": result}


@router.get("/dashboard/clusters/{cluster_id}")
async def cluster_inspector(cluster_id: str):
    result = dashboard_repo.cluster(cluster_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Cluster '{cluster_id}' not found.")
    return result
