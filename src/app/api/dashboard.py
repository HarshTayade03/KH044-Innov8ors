"""api/dashboard.py — Dashboard metrics endpoint. STUB — Full implementation in Module 7."""
from fastapi import APIRouter
router = APIRouter(tags=["Dashboard"])

@router.get("/dashboard/metrics", status_code=501)
async def get_metrics(): return {"status": "not_implemented", "module": "F1-01"}
