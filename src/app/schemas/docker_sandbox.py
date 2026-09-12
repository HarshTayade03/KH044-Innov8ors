"""
Pydantic schemas for Small-Scale Ephemeral Docker Sandbox Execution.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class DockerStatusResponse(BaseModel):
    """Status contract for Docker engine availability and policy."""
    docker_available: bool = Field(..., description="True if Docker CLI / daemon is detected")
    policy_enabled: bool = Field(..., description="True if DOCKER_SANDBOX_ENABLED setting is true")
    engine_info: Optional[str] = Field(None, description="Docker daemon version or diagnostic string")
    isolation_mode: str = Field("network_none", description="Isolation constraints enforced")
    message: str = Field(..., description="Human-readable operational status summary")


class DockerExecutionRequest(BaseModel):
    """Request DTO to launch an ephemeral containerized validation probe."""
    scenario: str = Field("sqli", description="Target scenario (sqli, xss, ssrf)")
    timeout_seconds: int = Field(5, ge=1, le=30, description="Container execution timeout")
    memory_limit_mb: int = Field(64, ge=16, le=256, description="Memory limit in megabytes")


class DockerExecutionResult(BaseModel):
    """Result DTO of an ephemeral containerized validation probe."""
    canonical_issue_id: str = Field(..., description="Canonical issue ID tested")
    execution_status: str = Field(..., description="completed, docker_unavailable, disabled_by_policy, or error")
    container_id: Optional[str] = Field(None, description="Ephemeral container ID if executed")
    exit_code: Optional[int] = Field(None, description="Container process exit code")
    stdout_summary: str = Field("", description="Sanitized stdout snippet")
    stderr_summary: str = Field("", description="Sanitized stderr snippet")
    sha256_digest: str = Field(..., description="Digest over execution artifacts")
    execution_time_ms: float = Field(..., description="Execution duration in milliseconds")
    is_docker_executed: bool = Field(..., description="True if real Docker container ran")
    limitations: str = Field("Strict network isolation (network_mode=none) and 64MB RAM limit enforced.")
