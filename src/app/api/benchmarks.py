"""Authorized benchmark catalog endpoint."""

from fastapi import APIRouter

from src.app.schemas.benchmarks import BenchmarkCatalog
from src.app.services.benchmark_catalog import benchmark_catalog_service

router = APIRouter(tags=["Benchmarks"])


@router.get("/benchmarks", response_model=BenchmarkCatalog)
async def get_benchmark_catalog() -> BenchmarkCatalog:
    return benchmark_catalog_service.get_catalog()
