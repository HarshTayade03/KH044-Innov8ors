"""
services/docker_sandbox.py — Small-Scale Ephemeral Docker Sandbox Execution.

Executes short-lived, containerized validation probes under strict isolation constraints
(network_mode="none", memory limit 64MB, execution timeout 5s) when Docker is available.
Includes safe diagnostics and fallback when Docker daemon is absent or disabled by policy.
"""

import hashlib
import logging
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

from src.app.config import settings
from src.app.schemas.docker_sandbox import DockerStatusResponse, DockerExecutionResult

logger = logging.getLogger(__name__)


class DockerSandboxService:
    """Service for small-scale ephemeral Docker sandbox execution."""

    def check_docker_availability(self) -> DockerStatusResponse:
        """Inspect host operating system for Docker CLI and running daemon."""
        docker_cli = shutil.which("docker")
        if not docker_cli:
            return DockerStatusResponse(
                docker_available=False,
                policy_enabled=getattr(settings, "docker_sandbox_enabled", False),
                engine_info=None,
                isolation_mode="network_none",
                message="Docker CLI binary not found on system PATH.",
            )

        try:
            res = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if res.returncode == 0:
                version = res.stdout.strip()
                return DockerStatusResponse(
                    docker_available=True,
                    policy_enabled=getattr(settings, "docker_sandbox_enabled", False),
                    engine_info=f"Docker Engine v{version}",
                    isolation_mode="network_none",
                    message=f"Docker Engine v{version} detected and operational.",
                )
            else:
                return DockerStatusResponse(
                    docker_available=False,
                    policy_enabled=getattr(settings, "docker_sandbox_enabled", False),
                    engine_info=None,
                    isolation_mode="network_none",
                    message="Docker CLI present, but Docker daemon is not running or accessible.",
                )
        except Exception as e:
            return DockerStatusResponse(
                docker_available=False,
                policy_enabled=getattr(settings, "docker_sandbox_enabled", False),
                engine_info=None,
                isolation_mode="network_none",
                message=f"Docker engine probe failed: {str(e)}",
            )

    def run_ephemeral_probe(
        self,
        canonical_issue_id: str,
        scenario: str = "sqli",
        timeout_seconds: int = 5,
        memory_limit_mb: int = 64,
    ) -> DockerExecutionResult:
        """
        Run a containerized probe under tight network & resource isolation.
        """
        start_time = time.time()
        status_info = self.check_docker_availability()
        policy_enabled = getattr(settings, "docker_sandbox_enabled", False)

        # Policy guard: Real Docker execution requires explicit configuration
        if not policy_enabled:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            digest = hashlib.sha256(f"disabled_by_policy:{canonical_issue_id}".encode("utf-8")).hexdigest()
            return DockerExecutionResult(
                canonical_issue_id=canonical_issue_id,
                execution_status="disabled_by_policy",
                container_id=None,
                exit_code=None,
                stdout_summary="Docker sandbox execution disabled by policy (DOCKER_SANDBOX_ENABLED=false).",
                stderr_summary="",
                sha256_digest=digest,
                execution_time_ms=duration_ms,
                is_docker_executed=False,
                limitations="Real sandbox execution disabled by default per security policy.",
            )

        # Availability guard: Docker daemon must be running
        if not status_info.docker_available:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            digest = hashlib.sha256(f"docker_unavailable:{canonical_issue_id}".encode("utf-8")).hexdigest()
            return DockerExecutionResult(
                canonical_issue_id=canonical_issue_id,
                execution_status="docker_unavailable",
                container_id=None,
                exit_code=None,
                stdout_summary=f"Docker unavailable: {status_info.message}",
                stderr_summary="",
                sha256_digest=digest,
                execution_time_ms=duration_ms,
                is_docker_executed=False,
                limitations="Host environment lacks running Docker daemon.",
            )

        # Execute container under strict isolation flags
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--memory", f"{memory_limit_mb}m",
            "--cpus", "0.5",
            "alpine:latest",
            "sh", "-c",
            f"echo '[VULNTRIAGER-DOCKER] Probe executing under network=none {memory_limit_mb}MB limit'; echo 'Scenario: {scenario}'; echo 'Verdict: SIMULATED_PROBE_COMPLETE'"
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            duration_ms = round((time.time() - start_time) * 1000, 2)
            raw_output = f"{res.stdout}\n{res.stderr}".encode("utf-8")
            digest = hashlib.sha256(raw_output).hexdigest()

            return DockerExecutionResult(
                canonical_issue_id=canonical_issue_id,
                execution_status="completed" if res.returncode == 0 else "error",
                container_id="ephemeral-alpine",
                exit_code=res.returncode,
                stdout_summary=res.stdout.strip()[:500],
                stderr_summary=res.stderr.strip()[:500],
                sha256_digest=digest,
                execution_time_ms=duration_ms,
                is_docker_executed=True,
                limitations="Strict network isolation (network_mode=none) and RAM limits enforced.",
            )
        except subprocess.TimeoutExpired:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            digest = hashlib.sha256(f"timeout:{canonical_issue_id}".encode("utf-8")).hexdigest()
            return DockerExecutionResult(
                canonical_issue_id=canonical_issue_id,
                execution_status="timeout",
                container_id=None,
                exit_code=124,
                stdout_summary="",
                stderr_summary=f"Container execution timed out after {timeout_seconds} seconds.",
                sha256_digest=digest,
                execution_time_ms=duration_ms,
                is_docker_executed=True,
                limitations=f"Probe exceeded timeout limit of {timeout_seconds}s.",
            )
        except Exception as e:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            digest = hashlib.sha256(f"error:{str(e)}".encode("utf-8")).hexdigest()
            return DockerExecutionResult(
                canonical_issue_id=canonical_issue_id,
                execution_status="error",
                container_id=None,
                exit_code=1,
                stdout_summary="",
                stderr_summary=f"Docker run error: {str(e)}",
                sha256_digest=digest,
                execution_time_ms=duration_ms,
                is_docker_executed=False,
                limitations="Exception raised during container creation.",
            )
