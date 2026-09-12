"""Metrics and fixed synthetic-dataset controls for the demonstration UI."""
from pathlib import Path
from fastapi import APIRouter, HTTPException
from src.app.api.ingestion import parse_json_or_sarif_file_content
from src.app.repositories.dashboard_repo import dashboard_repo
from src.app.schemas.dashboard import DashboardMetrics
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
    "workflow-sample": ("sample_workflow_upload.json", "sample", "Mixed workflow sample", 6),
}

@router.get("/demo/datasets")
async def list_demo_datasets():
    return {"total_findings": sum(value[3] for value in DATASETS.values()), "datasets": [
        {"id": key, "filename": value[0], "scanner": value[1], "category": value[2], "count": value[3],
         "origin": "included workflow resource" if key == "workflow-sample" else "repository fixture"}
        for key, value in DATASETS.items()
    ]}

@router.post("/demo/datasets/{dataset_id}/load")
async def load_demo_dataset(dataset_id: str):
    item = DATASETS.get(dataset_id)
    if not item: raise HTTPException(status_code=404, detail=f"Synthetic dataset '{dataset_id}' not found.")
    filename, scanner, _, _ = item
    records, _ = parse_json_or_sarif_file_content((DATA_DIR / filename).read_text(encoding="utf-8"))
    return normalizer_service.normalize_batch(records, scanner, source_file=filename)


@router.get("/dashboard/metrics", response_model=DashboardMetrics)
async def get_metrics() -> DashboardMetrics:
    return dashboard_repo.metrics()
