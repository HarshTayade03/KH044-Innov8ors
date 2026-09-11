"""Offline lab validation and evidence endpoints."""
from fastapi import APIRouter, HTTPException
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.validation import EvidenceResponse, ValidationRequest, ValidationResult
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

@router.get("/validations/{validation_id}", response_model=ValidationResult)
async def get_validation(validation_id: str):
    result = validation_repo.get(validation_id)
    if not result: raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    return result

@router.get("/validations/{validation_id}/evidence", response_model=EvidenceResponse)
async def get_validation_evidence(validation_id: str):
    if not validation_repo.get(validation_id): raise HTTPException(status_code=404, detail=f"Validation '{validation_id}' not found.")
    return EvidenceResponse(validation_id=validation_id, artifacts=validation_repo.list_artifacts(validation_id))
