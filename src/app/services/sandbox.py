"""Safe deterministic validation simulator; performs no network or process execution."""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from src.app.config import settings
from src.app.parsers.base import resolve_cwe_root
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.validation import (
    Artifact,
    SandboxMode,
    ValidationBatchFailure,
    ValidationBatchResponse,
    ValidationRequest,
    ValidationResult,
    ValidationStatus,
)
from src.app.services.extractor import redact_secrets

SCENARIOS = {"CWE-89": "sqli", "CWE-79": "xss", "CWE-918": "ssrf"}
LIMITATION = "Deterministic offline simulation only; this result does not prove real exploitability."
class ValidationRejected(ValueError): pass


def _create_artifact(validation_id: str, artifact_type: str, content: str, now: datetime, metadata: dict | None = None) -> Artifact:
    redacted = redact_secrets(content) or ""
    retained = redacted.encode("utf-8")
    meta = {"simulation": True, **(metadata or {})}
    return Artifact(
        artifact_id=f"art-{uuid.uuid4()}",
        validation_id=validation_id,
        artifact_type=artifact_type,
        content=redacted,
        content_hash=hashlib.sha256(retained).hexdigest(),
        content_size=len(retained),
        redacted=True,
        metadata=meta,
        created_at=now,
    )


class SandboxService:
    def validate(self, issue_id: str, request: ValidationRequest) -> ValidationResult:
        issue = dedup_repo.get_canonical_issue(issue_id)
        if not issue or not issue.active:
            raise LookupError(f"Canonical issue '{issue_id}' not found.")
        if request.mode == SandboxMode.DOCKER:
            raise ValidationRejected("Docker sandbox execution is not implemented and remains disabled.")
        if not issue.source_finding_ids:
            raise LookupError(f"Canonical issue '{issue_id}' has no source findings.")
        finding = findings_repo.get_normalized_finding(issue.source_finding_ids[0])
        if not finding:
            raise LookupError(f"Source finding for canonical issue '{issue_id}' not found.")

        raw_host = request.target_host or finding.location.host or ""
        host = urlparse(raw_host if "://" in raw_host else f"//{raw_host}").hostname or raw_host
        if host not in settings.sandbox_allowlist_set:
            raise ValidationRejected(f"Target host '{host}' is not in the configured lab allowlist.")

        cwes = [finding.vulnerability.cwe_primary, *finding.vulnerability.cwe_ids]
        resolved_cwes = [resolve_cwe_root(c) for c in cwes if c]
        expected = next((SCENARIOS[c] for c in resolved_cwes if c in SCENARIOS), None)
        scenario = (request.scenario or expected or "unknown").lower()
        param = finding.location.parameter or "input"
        path = finding.location.path or "/api/v1/resource"

        now = datetime.now(timezone.utc)
        validation_id = f"val-{uuid.uuid4()}"
        artifacts: list[Artifact] = []

        if request.simulate_timeout:
            status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, "Lab simulation timed out before producing a result."
            log = (f"[00.000s] [SANDBOX-INIT] Launching ephemeral simulator container mode=lab_simulator target={host}\n"
                   f"[00.010s] [ALLOWLIST-CHECK] Target host '{host}' verified against SANDBOX_ALLOWLIST\n"
                   f"[00.020s] [DISPATCH] Probing {path} on parameter '{param}' with {scenario.upper()} payload\n"
                   f"[{settings.sandbox_timeout_seconds}.000s] [TIMEOUT] Execution exceeded configured timeout of {settings.sandbox_timeout_seconds}s\n"
                   f"[{settings.sandbox_timeout_seconds}.005s] [TERMINATED] Process aborted. Outcome: INCONCLUSIVE")
            req_content = f"GET {path}?{param}=probe HTTP/1.1\nHost: {host}\nUser-Agent: VulnTriager-Sandbox/1.0"
            resp_content = f"HTTP/1.1 504 Gateway Timeout\nContent-Type: text/plain\n\nSimulation timed out."
        elif scenario not in set(SCENARIOS.values()):
            status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, f"Unsupported lab scenario '{scenario}'."
            log = (f"[00.000s] [SANDBOX-INIT] Launching simulator for scenario '{scenario}'\n"
                   f"[00.010s] [UNSUPPORTED] No deterministic lab simulation fixture available for '{scenario}'\n"
                   f"[00.012s] [COMPLETE] Outcome: INCONCLUSIVE (unsupported scenario)")
            req_content = f"GET {path} HTTP/1.1\nHost: {host}"
            resp_content = "HTTP/1.1 501 Not Implemented\n\nNo simulation scenario available."
        elif scenario == expected:
            status, confidence, summary = ValidationStatus.SIMULATED_MATCH, 0.75, f"Offline {scenario.upper()} fixture matched the finding classification."
            if scenario == "sqli":
                req_content = f"GET {path}?{param}=' OR '1'='1 HTTP/1.1\nHost: {host}\nUser-Agent: VulnTriager-Sandbox/1.0\nAccept: application/json"
                resp_content = ("HTTP/1.1 500 Internal Server Error\nContent-Type: application/json\n\n"
                                '{"error": "SQL syntax error: unclosed quotation mark near \'1\'=\'1\'", "code": "DB_ERR_SYNTAX"}')
            elif scenario == "xss":
                req_content = (f"POST {path} HTTP/1.1\nHost: {host}\nContent-Type: application/x-www-form-urlencoded\n\n"
                               f"{param}=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
                resp_content = (f"HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\n\n"
                                f"<html><body>Search query: <script>alert(1)</script></body></html>")
            else: # ssrf
                req_content = (f"POST {path} HTTP/1.1\nHost: {host}\nContent-Type: application/json\n\n"
                               f'{{"{param}": "http://169.254.169.254/latest/meta-data/"}}')
                resp_content = ("HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
                                "ami-id\ninstance-id\ninstance-type\nlocal-hostname")

            log = (f"[00.000s] [SANDBOX-INIT] Mode=lab_simulator target={host} timeout={settings.sandbox_timeout_seconds}s\n"
                   f"[00.008s] [ALLOWLIST-CHECK] Host '{host}' verified against configured allowlist\n"
                   f"[00.015s] [PROBE-DISPATCH] Injected non-destructive {scenario.upper()} probe on parameter '{param}'\n"
                   f"[00.038s] [RESPONSE-EVAL] Observed matching vulnerability behavior (confidence {confidence})\n"
                   f"[00.042s] [VERDICT] SIMULATED_MATCH — finding classification confirmed in offline lab environment")
        else:
            status, confidence, summary = ValidationStatus.SIMULATED_NO_MATCH, 0.6, f"Offline {scenario.upper()} fixture did not match the finding classification."
            req_content = f"GET {path}?{param}=safe_test HTTP/1.1\nHost: {host}\nUser-Agent: VulnTriager-Sandbox/1.0"
            resp_content = ("HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
                            '{"status": "ok", "sanitized": true, "records": []}')
            log = (f"[00.000s] [SANDBOX-INIT] Mode=lab_simulator target={host}\n"
                   f"[00.009s] [PROBE-DISPATCH] Dispatched test probe for scenario '{scenario}'\n"
                   f"[00.035s] [RESPONSE-EVAL] Target rejected or sanitized probe; expected vulnerability signature absent\n"
                   f"[00.040s] [VERDICT] SIMULATED_NO_MATCH — simulated outcome did not match classification")

        # Create validation_summary first (index 0 for backward compatibility with existing tests)
        summary_content = json.dumps({
            "simulation": True,
            "scenario": scenario,
            "target_host": host,
            "finding_id": finding.finding_id,
            "status": status.value,
            "summary": summary,
            "source_excerpt": finding.evidence.summary or "",
        }, sort_keys=True)
        summary_artifact = _create_artifact(validation_id, "validation_summary", summary_content, now, {"content_type": "application/json"})
        artifacts.append(summary_artifact)

        # Multi-artifact evidence: probe request, server response, execution log
        artifacts.append(_create_artifact(validation_id, "http_request", req_content, now, {"content_type": "text/plain", "parameter": param}))
        artifacts.append(_create_artifact(validation_id, "http_response", resp_content, now, {"content_type": "text/plain"}))
        artifacts.append(_create_artifact(validation_id, "execution_log", log, now, {"content_type": "text/plain"}))

        result = ValidationResult(
            validation_id=validation_id,
            canonical_issue_id=issue_id,
            finding_id=finding.finding_id,
            status=status,
            confidence=confidence,
            sandbox_mode=request.mode,
            scenario=scenario,
            target_host=host,
            execution_summary=summary,
            limitations=[LIMITATION],
            executed_at=now,
            timeout_seconds=settings.sandbox_timeout_seconds,
            artifact_ids=[a.artifact_id for a in artifacts],
            created_at=now,
        )
        validation_repo.save(result, artifacts)
        return result

    def validate_batch(self, request: ValidationRequest | None = None) -> ValidationBatchResponse:
        if request is None:
            request = ValidationRequest()
        issues = dedup_repo.list_canonical_issues()
        results = []
        failures: list[ValidationBatchFailure] = []
        for issue in issues:
            try:
                res = self.validate(issue.canonical_issue_id, request)
                results.append(res)
            except (LookupError, ValidationRejected, ValueError) as exc:
                failures.append(ValidationBatchFailure(
                    canonical_issue_id=issue.canonical_issue_id,
                    error=str(exc),
                ))
        return ValidationBatchResponse(results=results, failures=failures)


sandbox_service = SandboxService()
