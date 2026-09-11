"""
api/ingestion.py — Finding ingestion API endpoints.

Handles:
- File upload (SARIF 2.1.0 and JSON formats)
- Direct JSON array POST
- Manual Entry Form submission
"""

import json
from typing import Optional
from fastapi import APIRouter, File, UploadFile, Form, HTTPException, status

from src.app.schemas.canonical import (
    BatchSummary,
    DirectIngestPayload,
    ManualFindingCreate,
)
from src.app.services.normalizer import normalizer_service

router = APIRouter(tags=["Ingestion"])


def parse_json_or_sarif_file_content(content_str: str) -> tuple[list[dict], Optional[str]]:
    """
    Parse uploaded JSON string. Handles:
    1. SARIF format (top-level dict with 'runs' key)
    2. JSON array of findings
    3. Single JSON finding object
    Returns (list_of_records, detected_format_hint)
    """
    try:
        data = json.loads(content_str)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON format: {str(e)}",
        )

    if isinstance(data, dict):
        # SARIF check
        if "runs" in data and isinstance(data["runs"], list):
            sarif_records = []
            for run in data["runs"]:
                results = run.get("results", [])
                tool_info = run.get("tool", {}).get("driver", {})
                for res in results:
                    # Enrich each result with run tool metadata
                    if isinstance(res, dict):
                        res["__sarif_tool__"] = tool_info.get("name")
                        res["__sarif_version__"] = tool_info.get("version")
                        sarif_records.append(res)
            return sarif_records, "sarif"
        else:
            # Single object finding
            return [data], "json_single"

    elif isinstance(data, list):
        return data, "json_array"

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JSON root must be an Object (SARIF/single finding) or an Array of findings.",
        )


@router.post("/findings/upload", response_model=BatchSummary, status_code=status.HTTP_201_CREATED)
async def upload_findings_file(
    file: UploadFile = File(...),
    source_scanner: str = Form(...),
):
    """
    Upload a JSON or SARIF 2.1.0 scanner output file.
    Supports Nessus, Burp, ZAP, Snyk, Trivy, and SARIF files.
    """
    try:
        contents = await file.read()
        content_str = contents.decode("utf-8")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file: {str(e)}",
        )

    records, format_hint = parse_json_or_sarif_file_content(content_str)
    if not records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file contains no finding records.",
        )

    scanner = source_scanner.lower().strip()
    if format_hint == "sarif" and scanner not in ["sarif", "burp", "nessus", "zap"]:
        scanner = "sarif"

    batch_summary = normalizer_service.normalize_batch(
        records=records,
        source_scanner=scanner,
        source_file=file.filename,
    )
    return batch_summary


@router.post("/findings", response_model=BatchSummary, status_code=status.HTTP_201_CREATED)
async def ingest_findings_json(payload: DirectIngestPayload):
    """
    Direct POST endpoint for sending a JSON array of scanner findings programmatically.
    """
    if not payload.findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'findings' array cannot be empty.",
        )

    return normalizer_service.normalize_batch(
        records=payload.findings,
        source_scanner=payload.source_scanner.lower().strip(),
        source_file="direct_api_post",
    )


@router.post("/findings/manual", status_code=status.HTTP_201_CREATED)
async def manual_finding_entry(entry: ManualFindingCreate):
    """
    Manual Entry Form endpoint — allows an analyst to enter a single vulnerability manually.
    """
    finding = normalizer_service.normalize_manual_entry(entry)
    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "normalization_status": finding.quality.normalization_status,
        "completeness_score": finding.quality.completeness_score,
        "source_scanner": finding.source_scanner,
        "title": finding.vulnerability.title,
    }
