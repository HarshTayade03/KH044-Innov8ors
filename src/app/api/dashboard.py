"""Metrics and fixed synthetic-dataset controls for the demonstration UI."""
from fastapi import APIRouter, HTTPException
from src.app.database import get_db
from src.app.services.demo import DATASETS, load_dataset

router = APIRouter(tags=["Dashboard"])

@router.get("/demo/datasets")
async def list_demo_datasets():
    return {"total_findings": 110, "datasets": [
        {"id": key, "filename": value[0], "scanner": value[1], "category": value[2], "count": value[3]}
        for key, value in DATASETS.items()
    ]}

@router.post("/demo/datasets/{dataset_id}/load")
async def load_demo_dataset(dataset_id: str):
    try:
        return load_dataset(dataset_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=503, detail='Synthetic import failed; no partial batch was retained.') from exc

@router.get("/dashboard/metrics")
async def get_metrics():
    with get_db() as db:
        counts = {table: db.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"] for table in
                  ("normalized_findings", "canonical_issues", "clusters", "priorities", "validation_runs", "artifacts")}
        active = db.execute("SELECT COUNT(*) AS n FROM canonical_issues WHERE active=1").fetchone()["n"]
    return {"findings": counts["normalized_findings"], "active_issues": active,
            "clusters": counts["clusters"], "priorities": counts["priorities"],
            "validations": counts["validation_runs"], "artifacts": counts["artifacts"]}
