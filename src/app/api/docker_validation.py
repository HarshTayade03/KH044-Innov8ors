"""
API router for Small-Scale Ephemeral Docker Sandbox Execution.
"""

from fastapi import APIRouter, HTTPException
from src.app.repositories.dedup_repo import dedup_repo
from src.app.schemas.docker_sandbox import (
    DockerExecutionRequest,
    DockerExecutionResult,
    DockerStatusResponse,
)
from src.app.services.docker_sandbox import DockerSandboxService

router = APIRouter(tags=["Docker Sandbox"])
docker_service = DockerSandboxService()


@router.get("/sandbox/docker/status", response_model=DockerStatusResponse)
async def get_docker_status():
    """
    Inspect host operating system for Docker engine availability and policy status.
    """
    return docker_service.check_docker_availability()


@router.post("/sandbox/docker/execute/{canonical_issue_id}", response_model=DockerExecutionResult)
async def execute_docker_probe(canonical_issue_id: str, request: DockerExecutionRequest | None = None):
    """
    Launch an ephemeral, network-isolated containerized validation probe for a canonical issue.
    """
    issue = dedup_repo.get_canonical_issue(canonical_issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail=f"Canonical issue '{canonical_issue_id}' not found.")

    scenario = request.scenario if request else "sqli"
    timeout = request.timeout_seconds if request else 5
    mem_limit = request.memory_limit_mb if request else 64

    return docker_service.run_ephemeral_probe(
        canonical_issue_id=canonical_issue_id,
        scenario=scenario,
        timeout_seconds=timeout,
        memory_limit_mb=mem_limit,
    )
