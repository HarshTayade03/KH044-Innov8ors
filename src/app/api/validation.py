"""Offline lab validation and evidence endpoints."""
from fastapi import APIRouter, HTTPException, Query
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.validation_repo import EvidenceIntegrityError, validation_repo
from src.app.schemas.validation import (
    BatchValidationRequest,
    BatchValidationResponse,
    EvidenceResponse,
    ValidationListResponse,
    ValidationRequest,
    ValidationResult,
    ValidationStatus,
)
from src.app.services.sandbox import ValidationRejected, sandbox_service

router = APIRouter(tags=["Validation"])

@router.get("/validations", response_model=ValidationListResponse)
async def list_validations(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    items = validation_repo.list_all(limit=limit, offset=offset)
    return ValidationListResponse(total=len(items), validations=items)

@router.post("/canonical-issues/{canonical_issue_id}/validate", response_model=ValidationResult)
async def validate_issue(canonical_issue_id: str, request: ValidationRequest):
    try:
        return sandbox_service.validate(canonical_issue_id, request)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValidationRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@router.get("/canonical-issues/{canonical_issue_id}/validations", response_model=list[ValidationResult])
async def list_issue_validations(canonical_issue_id: str):
    issue = dedup_repo.get_canonical_issue(canonical_issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail=f"Canonical issue '{canonical_issue_id}' not found.")
    return validation_repo.list_for_issue(canonical_issue_id)

@router.post("/validations/batch", response_model=BatchValidationResponse)
async def validate_batch(request: BatchValidationRequest = BatchValidationRequest()):
    target_ids = request.canonical_issue_ids
    if not target_ids:
        active_issues = dedup_repo.list_canonical_issues()
        target_ids = [issue.canonical_issue_id for issue in active_issues if issue.active]

    results: list[ValidationResult] = []
    matched = 0
    no_match = 0
    inconclusive = 0

    single_req = ValidationRequest(mode=request.mode, simulate_timeout=request.simulate_timeout)
    for issue_id in target_ids:
        try:
            res = sandbox_service.validate(issue_id, single_req)
            results.append(res)
            if res.status == ValidationStatus.SIMULATED_MATCH:
                matched += 1
            elif res.status == ValidationStatus.SIMULATED_NO_MATCH:
                no_match += 1
            else:
                inconclusive += 1
        except Exception:
            # Continue validating remaining issues in batch
            continue

    return BatchValidationResponse(
        total_issues=len(target_ids),
        validated_count=len(results),
        matched_count=matched,
        no_match_count=no_match,
        inconclusive_count=inconclusive,
        results=results,
    )

@router.get("/validations/{validation_id}", response_model=ValidationResult)
async def get_validation(validation_id: str):
    result = validation_repo.get(validation_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    return result

@router.get("/validations/{validation_id}/evidence", response_model=EvidenceResponse)
async def get_validation_evidence(validation_id: str):
    if not validation_repo.get(validation_id):
        raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    try:
        artifacts = validation_repo.list_artifacts(validation_id)
    except EvidenceIntegrityError as exc:
        raise HTTPException(status_code=500, detail="Stored evidence failed integrity verification.") from exc
    return EvidenceResponse(validation_id=validation_id, artifacts=artifacts)

