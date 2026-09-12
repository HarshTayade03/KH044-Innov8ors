"""Offline lab validation and evidence endpoints."""
import asyncio
import json
from queue import Empty, Queue
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.validation import EvidenceResponse, ValidationHistoryResponse, ValidationRequest, ValidationResult, ValidationTraceResponse
from src.app.services.sandbox import ValidationRejected, sandbox_service

router = APIRouter(tags=["Validation"])

@router.post("/canonical-issues/{canonical_issue_id}/validate", response_model=ValidationResult)
async def validate_issue(canonical_issue_id: str, request: ValidationRequest):
    try:
        return sandbox_service.validate(canonical_issue_id, request)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValidationRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/canonical-issues/{canonical_issue_id}/validate/stream")
async def stream_validation(canonical_issue_id: str, request: ValidationRequest):
    """Stream explainability events while the offline simulator performs its checks."""
    events: Queue = Queue()

    def encode(event_type: str, payload: dict) -> str:
        return f"event: {event_type}\ndata: {json.dumps(payload, default=str)}\n\n"

    async def event_stream():
        yield encode("validation_started", {"canonical_issue_id": canonical_issue_id, "live_execution": False})
        task = asyncio.create_task(asyncio.to_thread(
            sandbox_service.validate,
            canonical_issue_id,
            request,
            events.put,
        ))
        while not task.done() or not events.empty():
            try:
                step = await asyncio.to_thread(events.get, True, 0.05)
            except Empty:
                continue
            yield encode("trace_step", step.model_dump(mode="json"))
        try:
            result = await task
        except LookupError as exc:
            yield encode("validation_error", {"status": 404, "detail": str(exc)})
            return
        except ValidationRejected as exc:
            yield encode("validation_error", {"status": 422, "detail": str(exc)})
            return
        yield encode("validation_complete", {"live_execution": False, "result": result.model_dump(mode="json")})

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@router.get("/validations/{validation_id}", response_model=ValidationResult)
async def get_validation(validation_id: str):
    result = validation_repo.get(validation_id)
    if not result: raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    return result

@router.get("/validations/{validation_id}/evidence", response_model=EvidenceResponse)
async def get_validation_evidence(validation_id: str):
    if not validation_repo.get(validation_id): raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    return EvidenceResponse(validation_id=validation_id, artifacts=validation_repo.list_artifacts(validation_id))


@router.get("/validations/{validation_id}/trace", response_model=ValidationTraceResponse)
async def get_validation_trace(validation_id: str):
    result = validation_repo.get(validation_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    return ValidationTraceResponse(validation_id=validation_id, trace=result.trace)


@router.get("/canonical-issues/{canonical_issue_id}/validations", response_model=ValidationHistoryResponse)
async def list_issue_validations(
    canonical_issue_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    issue = dedup_repo.get_canonical_issue(canonical_issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail=f"Canonical issue '{canonical_issue_id}' not found.")
    validations = validation_repo.list_for_issue(canonical_issue_id, limit=limit, offset=offset)
    return ValidationHistoryResponse(
        canonical_issue_id=canonical_issue_id,
        total=validation_repo.count_for_issue(canonical_issue_id),
        limit=limit,
        offset=offset,
        validations=validations,
    )
