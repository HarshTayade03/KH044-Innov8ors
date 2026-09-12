"""Dashboard metrics endpoint for the analyst console."""

from fastapi import APIRouter
from src.app.repositories.dashboard_repo import dashboard_repo
from src.app.schemas.dashboard import DashboardMetrics

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard/metrics", response_model=DashboardMetrics)
async def get_metrics() -> DashboardMetrics:
    return dashboard_repo.metrics()
