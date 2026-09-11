"""api/validation.py — Sandbox validation endpoints. STUB — Full implementation in Module 5 (M5-06)."""
from fastapi import APIRouter
router = APIRouter(tags=["Validation"])

@router.post("/canonical-issues/{canonical_issue_id}/validate", status_code=501)
async def validate_issue(canonical_issue_id: str): return {"status": "not_implemented", "module": "M5-06"}

@router.get("/validations/{validation_id}", status_code=501)
async def get_validation(validation_id: str): return {"status": "not_implemented", "module": "M5-06"}

@router.get("/validations/{validation_id}/evidence", status_code=501)
async def get_validation_evidence(validation_id: str): return {"status": "not_implemented", "module": "M5-06"}
