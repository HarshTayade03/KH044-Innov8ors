"""Metrics and fixed synthetic-dataset controls for the demonstration UI."""
from fastapi import APIRouter, HTTPException
from src.app.repositories.dashboard_repo import dashboard_repo
from src.app.schemas.dashboard import DashboardMetrics
from src.app.services.demo import DATASETS, load_dataset

router = APIRouter(tags=["Dashboard"])

@router.get("/demo/datasets")
async def list_demo_datasets():
    return {"total_findings": sum(value[3] for value in DATASETS.values()), "datasets": [
        {"id": key, "filename": value[0], "scanner": value[1], "category": value[2], "count": value[3],
         "origin": "included workflow resource" if key == "workflow-sample" else "repository fixture"}
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


@router.get("/dashboard/metrics", response_model=DashboardMetrics)
async def get_metrics() -> DashboardMetrics:
    return dashboard_repo.metrics()
