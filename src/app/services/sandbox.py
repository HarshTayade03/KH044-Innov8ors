"""Safe deterministic validation simulator; performs no network or process execution."""
import hashlib
import json
import uuid
from datetime import datetime, timezone
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


def _create_artifact(validation_id: str, artifact_type: str, content: str, created_at: datetime, metadata: dict | None = None) -> Artifact:
    redacted_content = redact_secrets(content) or ""
    retained = redacted_content.encode("utf-8")
    meta = {"simulation": True, "hash_encoding": "utf-8", **(metadata or {})}
    return Artifact(
        artifact_id=f"art-{uuid.uuid4()}",
        validation_id=validation_id,
        artifact_type=artifact_type,
        content=redacted_content,
        content_hash=hashlib.sha256(retained).hexdigest(),
        content_size=len(retained),
        redacted=True,
        metadata=meta,
        created_at=created_at,
    )


class SandboxService:
    def validate(self, issue_id: str, request: ValidationRequest) -> ValidationResult:
        issue = dedup_repo.get_canonical_issue(issue_id)
        if not issue or not issue.active:
            raise LookupError(f"Canonical issue '{issue_id}' not found.")
        if request.mode == SandboxMode.DOCKER:
            raise ValidationRejected("Docker sandbox execution is not implemented and remains disabled.")
        finding = findings_repo.get_normalized_finding(issue.source_finding_ids[0])
        if not finding:
            raise LookupError(f"Source finding for canonical issue '{issue_id}' not found.")

        host = request.target_host or finding.location.host or ""
        if host not in settings.sandbox_allowlist_set:
            raise ValidationRejected(f"Target host '{host}' is not in the configured lab allowlist.")

        all_cwes = [finding.vulnerability.cwe_primary, *finding.vulnerability.cwe_ids]
        resolved_cwes = [resolve_cwe_root(cwe) for cwe in all_cwes if cwe]
        resolved_cwes = [c for c in resolved_cwes if c]

        expected = next((SCENARIOS[cwe] for cwe in resolved_cwes if cwe in SCENARIOS), None)
        scenario = (request.scenario or expected or "unknown").lower()

        if request.simulate_timeout:
            status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, "Lab simulation timed out before producing a result."
        elif scenario not in set(SCENARIOS.values()):
            status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, f"Unsupported lab scenario '{scenario}'."
        elif scenario == expected:
            status, confidence, summary = ValidationStatus.SIMULATED_MATCH, 0.75, f"Offline {scenario.upper()} fixture matched the finding classification."
        else:
            status, confidence, summary = ValidationStatus.SIMULATED_NO_MATCH, 0.6, f"Offline {scenario.upper()} fixture did not match the finding classification."

        now = datetime.now(timezone.utc)
        validation_id = f"val-{uuid.uuid4()}"
        path = finding.location.path or "/vulnerable/endpoint"

        if scenario == "sqli":
            req_text = f"GET {path}?id=1'%20OR%20'1'='1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AI-Assisted Triage-LabSimulator/1.0\r\nAccept: */*\r\n\r\n"
            resp_text = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Database Error</h1><p>SQLSTATE[42000]: Syntax error or access violation near '\\' OR \\'1\\'=\\'1\\''</p></body></html>"
        elif scenario == "xss":
            req_text = f"GET {path}?q=%3Cscript%3Ealert%28%22VT_TEST%22%29%3C%2Fscript%3E HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AI-Assisted Triage-LabSimulator/1.0\r\nAccept: text/html\r\n\r\n"
            resp_text = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Search results for: <script>alert(\"VT_TEST\")</script></body></html>"
        elif scenario == "ssrf":
            req_text = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\r\n{{\"url\": \"http://169.254.169.254/latest/meta-data/\"}}"
            resp_text = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"ami-id\": \"ami-0123456789abcdef0\", \"instance-id\": \"i-0lab123456789\"}}"
        else:
            req_text = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AI-Assisted Triage-LabSimulator/1.0\r\n\r\n"
            resp_text = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nGeneric lab response"

        log_text = (
            f"[LAB_EXECUTOR] Timestamp: {now.isoformat()}\n"
            f"[LAB_EXECUTOR] Target host '{host}' verified against sandbox allowlist.\n"
            f"[LAB_EXECUTOR] Finding CWEs: {all_cwes} -> Resolved CWEs: {resolved_cwes}\n"
            f"[LAB_EXECUTOR] Selected scenario: {scenario} (Expected: {expected})\n"
            f"[LAB_EXECUTOR] Execution mode: LAB_SIMULATOR (Offline deterministic run)\n"
            f"[LAB_EXECUTOR] Verdict: {status.value} (Confidence: {confidence})\n"
            f"[LAB_EXECUTOR] Summary: {summary}"
        )

        val_summary_content = json.dumps({
            "simulation": True,
            "scenario": scenario,
            "target_host": host,
            "finding_id": finding.finding_id,
            "status": status.value,
            "confidence": confidence,
            "summary": summary,
            "source_excerpt": finding.evidence.summary or ""
        }, sort_keys=True, indent=2)

        art_req = _create_artifact(validation_id, "http_request", req_text, now, {"content_type": "text/plain"})
        art_resp = _create_artifact(validation_id, "http_response", resp_text, now, {"content_type": "text/plain"})
        art_log = _create_artifact(validation_id, "execution_log", log_text, now, {"content_type": "text/plain"})
        art_summary = _create_artifact(validation_id, "validation_summary", val_summary_content, now, {"content_type": "application/json"})

        artifacts = [art_req, art_resp, art_log, art_summary]
        artifact_ids = [a.artifact_id for a in artifacts]

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
            artifact_ids=artifact_ids,
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
