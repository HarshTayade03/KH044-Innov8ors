"""Metrics and fixed synthetic-dataset controls for the demonstration UI."""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from src.app.api.ingestion import parse_json_or_sarif_file_content
from src.app.database import get_db
from src.app.services.normalizer import normalizer_service

router = APIRouter(tags=["Dashboard"])
DATA_DIR = Path(__file__).resolve().parents[3] / "data"
DATASETS = {
    "burp-sqli": ("burp_sqli.sarif", "burp", "SQL injection", 25),
    "nessus-sqli": ("nessus_sqli.json", "nessus", "SQL injection", 25),
    "burp-xss": ("burp_xss.sarif", "burp", "Cross-site scripting", 20),
    "zap-xss": ("zap_xss.json", "zap", "Cross-site scripting", 20),
    "burp-ssrf": ("burp_ssrf.json", "burp", "Server-side request forgery", 10),
    "nessus-ssrf": ("nessus_ssrf.sarif", "nessus", "Server-side request forgery", 10),
}

@router.get("/demo/datasets")
async def list_demo_datasets():
    return {"total_findings": 110, "datasets": [
        {"id": key, "filename": value[0], "scanner": value[1], "category": value[2], "count": value[3]}
        for key, value in DATASETS.items()
    ]}

@router.post("/demo/datasets/{dataset_id}/load")
async def load_demo_dataset(dataset_id: str):
    item = DATASETS.get(dataset_id)
    if not item: raise HTTPException(status_code=404, detail=f"Synthetic dataset '{dataset_id}' not found.")
    filename, scanner, _, _ = item
    records, _ = parse_json_or_sarif_file_content((DATA_DIR / filename).read_text(encoding="utf-8"))
    return normalizer_service.normalize_batch(records, scanner, source_file=filename)

@router.get("/dashboard/metrics")
async def get_metrics():
    with get_db() as db:
        counts = {table: db.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"] for table in
                  ("normalized_findings", "canonical_issues", "clusters", "priorities", "validation_runs", "artifacts")}
        active = db.execute("SELECT COUNT(*) AS n FROM canonical_issues WHERE active=1").fetchone()["n"]
    return {"findings": counts["normalized_findings"], "active_issues": active,
            "clusters": counts["clusters"], "priorities": counts["priorities"],
            "validations": counts["validation_runs"], "artifacts": counts["artifacts"]}
