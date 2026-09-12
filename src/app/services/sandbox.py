"""Safe deterministic validation simulator; performs no network or process execution."""
import hashlib, json, uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from src.app.config import settings
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.validation import Artifact, SandboxMode, ValidationRequest, ValidationResult, ValidationStatus, ValidationTraceStep
from src.app.services.extractor import redact_secrets

SCENARIOS = {"CWE-89": "sqli", "CWE-79": "xss", "CWE-918": "ssrf"}
LIMITATION = "Deterministic offline simulation only; this result does not prove real exploitability."
class ValidationRejected(ValueError): pass

class SandboxService:
    def validate(self, issue_id: str, request: ValidationRequest, trace_sink=None) -> ValidationResult:
        trace: list[ValidationTraceStep] = []
        started = datetime.now(timezone.utc)

        def record(stage: str, action: str, outcome: str, **details):
            step = ValidationTraceStep(sequence=len(trace) + 1, stage=stage, action=action,
                                       outcome=outcome, details=details, occurred_at=datetime.now(timezone.utc))
            trace.append(step)
            if trace_sink:
                trace_sink(step)

        record("request", "accepted offline validation request", "completed", mode=request.mode.value)
        issue = dedup_repo.get_canonical_issue(issue_id)
        if not issue or not issue.active: raise LookupError(f"Canonical issue '{issue_id}' not found.")
        record("issue", "loaded active canonical issue", "completed", canonical_issue_id=issue_id)
        if request.mode == SandboxMode.DOCKER:
            record("executor", "checked requested executor", "rejected", reason="Docker execution is disabled")
            raise ValidationRejected("Docker sandbox execution is not implemented and remains disabled.")
        finding = findings_repo.get_normalized_finding(issue.source_finding_ids[0])
        if not finding: raise LookupError(f"Source finding for canonical issue '{issue_id}' not found.")
        record("evidence", "selected source finding", "completed", finding_id=finding.finding_id, source_scanner=finding.source_scanner)
        raw_host = request.target_host or finding.location.host or ""
        host = urlparse(raw_host if "://" in raw_host else f"//{raw_host}").hostname or raw_host
        if host not in settings.sandbox_allowlist_set:
            record("safety", "checked lab host allowlist", "rejected", host=host)
            raise ValidationRejected(f"Target host '{host}' is not in the configured lab allowlist.")
        record("safety", "checked lab host allowlist", "completed", host=host, network_access=False)
        cwes = [finding.vulnerability.cwe_primary, *finding.vulnerability.cwe_ids]
        expected = next((SCENARIOS[cwe] for cwe in cwes if cwe in SCENARIOS), None)
        scenario = (request.scenario or expected or "unknown").lower()
        record("scenario", "selected controlled fixture", "completed", scenario=scenario, expected=scenario == expected)
        if request.simulate_timeout:
            status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, "Lab simulation timed out before producing a result."
            record("fixture", "compared finding classification", "inconclusive", reason="simulated timeout")
        elif scenario not in set(SCENARIOS.values()):
            status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, f"Unsupported lab scenario '{scenario}'."
            record("fixture", "compared finding classification", "inconclusive", reason="unsupported scenario")
        elif scenario == expected:
            status, confidence, summary = ValidationStatus.SIMULATED_MATCH, 0.75, f"Offline {scenario.upper()} fixture matched the finding classification."
            record("fixture", "compared finding classification", "matched", comparison="CWE mapping only")
        else:
            status, confidence, summary = ValidationStatus.SIMULATED_NO_MATCH, 0.6, f"Offline {scenario.upper()} fixture did not match the finding classification."
            record("fixture", "compared finding classification", "no_match", comparison="CWE mapping only")
        now, validation_id = datetime.now(timezone.utc), f"val-{uuid.uuid4()}"
        content = redact_secrets(json.dumps({"simulation": True, "scenario": scenario, "target_host": host, "finding_id": finding.finding_id, "status": status.value, "summary": summary, "source_excerpt": finding.evidence.summary or "", "trace": [step.model_dump(mode="json") for step in trace]}, sort_keys=True, default=str)) or ""
        record("evidence", "redacted derived artifact", "completed", secrets_removed=True)
        retained = content.encode("utf-8")
        record("integrity", "calculated SHA-256 over retained bytes", "completed", content_size=len(retained))
        artifact = Artifact(artifact_id=f"art-{uuid.uuid4()}", validation_id=validation_id, artifact_type="validation_summary", content=content, content_hash=hashlib.sha256(retained).hexdigest(), content_size=len(retained), metadata={"simulation": True, "content_type": "application/json"}, created_at=now)
        record("persistence", "stored validation result and evidence", "completed", validation_id=validation_id)
        trace_content = json.dumps({"simulation": True, "validation_id": validation_id, "trace": [step.model_dump(mode="json") for step in trace]}, sort_keys=True, default=str)
        trace_bytes = trace_content.encode("utf-8")
        trace_artifact = Artifact(artifact_id=f"art-{uuid.uuid4()}", validation_id=validation_id, artifact_type="sandbox_trace", content=trace_content, content_hash=hashlib.sha256(trace_bytes).hexdigest(), content_size=len(trace_bytes), metadata={"simulation": True, "content_type": "application/json", "live_execution": False}, created_at=now)
        result = ValidationResult(validation_id=validation_id, canonical_issue_id=issue_id, finding_id=finding.finding_id, status=status, confidence=confidence, sandbox_mode=request.mode, scenario=scenario, target_host=host, execution_summary=summary, limitations=[LIMITATION, "Trace records simulator actions; it is not a live target execution log."], executed_at=now, timeout_seconds=settings.sandbox_timeout_seconds, artifact_ids=[artifact.artifact_id, trace_artifact.artifact_id], trace=trace, created_at=now)
        validation_repo.save(result, [artifact])
        return result

sandbox_service = SandboxService()
