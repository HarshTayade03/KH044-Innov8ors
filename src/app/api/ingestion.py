"""
api/ingestion.py — Finding ingestion endpoints.
Handles file upload, direct JSON POST, and manual entry.
STUB — Full implementation in Module 1 (M1-11, M1-12).
"""

from fastapi import APIRouter

router = APIRouter(tags=["Ingestion"])


@router.post("/findings/upload", status_code=501)
async def upload_findings_file():
    """Upload a JSON or SARIF file from a scanner. STUB."""
    return {"status": "not_implemented", "module": "M1-11"}


@router.post("/findings", status_code=501)
async def ingest_findings_json():
    """Submit findings as a JSON array directly. STUB."""
    return {"status": "not_implemented", "module": "M1-11"}


@router.post("/findings/manual", status_code=501)
async def manual_finding_entry():
    """Enter a single finding manually via form/JSON. STUB."""
    return {"status": "not_implemented", "module": "M1-12"}


@router.get("/ingestion/batches/{batch_id}", status_code=501)
async def get_batch_status(batch_id: str):
    """Get status and summary of an ingestion batch. STUB."""
    return {"status": "not_implemented", "module": "M1-11"}
