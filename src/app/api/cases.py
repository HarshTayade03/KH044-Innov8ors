"""api/cases.py — Case generation and human review endpoints. STUB — Full implementation in Module 6 (M6-05)."""
from fastapi import APIRouter
router = APIRouter(tags=["Cases"])

@router.post("/canonical-issues/{canonical_issue_id}/prioritize", status_code=501)
async def prioritize_issue(canonical_issue_id: str): return {"status": "not_implemented", "module": "M4-07"}

@router.get("/priorities", status_code=501)
async def list_priorities(): return {"status": "not_implemented", "module": "M4-07"}

@router.post("/canonical-issues/{canonical_issue_id}/generate-case", status_code=501)
async def generate_case(canonical_issue_id: str): return {"status": "not_implemented", "module": "M6-05"}

@router.get("/cases", status_code=501)
async def list_cases(): return {"status": "not_implemented", "module": "M6-05"}

@router.get("/cases/{case_id}", status_code=501)
async def get_case(case_id: str): return {"status": "not_implemented", "module": "M6-05"}

@router.post("/cases/{case_id}/approve", status_code=501)
async def approve_case(case_id: str): return {"status": "not_implemented", "module": "M6-05"}

@router.post("/cases/{case_id}/reject", status_code=501)
async def reject_case(case_id: str): return {"status": "not_implemented", "module": "M6-05"}

@router.post("/cases/{case_id}/request-evidence", status_code=501)
async def request_evidence(case_id: str): return {"status": "not_implemented", "module": "M6-05"}

@router.post("/cases/{case_id}/override-priority", status_code=501)
async def override_priority(case_id: str): return {"status": "not_implemented", "module": "M6-05"}
