"""Offline lab validation and evidence endpoints."""
from fastapi import APIRouter, HTTPException
from src.app.repositories.validation_repo import EvidenceIntegrityError, validation_repo
from src.app.schemas.validation import (
    EvidenceResponse,
    ValidationBatchResponse,
    ValidationRequest,
    ValidationResult,
)
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

@router.post("/validations/batch", response_model=ValidationBatchResponse)
async def validate_batch(request: ValidationRequest | None = None):
    return sandbox_service.validate_batch(request)

@router.get("/validations", response_model=list[ValidationResult])
async def list_validations(limit: int = 100):
    return validation_repo.list_all(limit=limit)

@router.get("/canonical-issues/{canonical_issue_id}/validations", response_model=list[ValidationResult])
async def list_issue_validations(canonical_issue_id: str):
    return validation_repo.list_for_issue(canonical_issue_id)

@router.get("/validations/{validation_id}", response_model=ValidationResult)
async def get_validation(validation_id: str):
    result = validation_repo.get(validation_id)
    if not result: raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    return result

@router.get("/validations/{validation_id}/evidence", response_model=EvidenceResponse)
async def get_validation_evidence(validation_id: str):
    if not validation_repo.get(validation_id): raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    try:
        artifacts = validation_repo.list_artifacts(validation_id)
    except EvidenceIntegrityError as exc:
        raise HTTPException(status_code=500, detail="Stored evidence failed integrity verification.") from exc
    return EvidenceResponse(validation_id=validation_id, artifacts=artifacts)
