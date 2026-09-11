"""Safe deterministic validation simulator; performs no network or process execution."""
import hashlib, json, uuid
from datetime import datetime, timezone
from src.app.config import settings
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.validation_repo import validation_repo
from src.app.schemas.validation import Artifact, SandboxMode, ValidationRequest, ValidationResult, ValidationStatus
from src.app.services.extractor import redact_secrets

SCENARIOS = {"CWE-89": "sqli", "CWE-79": "xss", "CWE-918": "ssrf"}
LIMITATION = "Deterministic offline simulation only; this result does not prove real exploitability."
class ValidationRejected(ValueError): pass

class SandboxService:
    def validate(self, issue_id: str, request: ValidationRequest) -> ValidationResult:
        issue = dedup_repo.get_canonical_issue(issue_id)
        if not issue or not issue.active: raise LookupError(f"Canonical issue '{issue_id}' not found.")
        if request.mode == SandboxMode.DOCKER: raise ValidationRejected("Docker sandbox execution is not implemented and remains disabled.")
        finding = findings_repo.get_normalized_finding(issue.source_finding_ids[0])
        if not finding: raise LookupError(f"Source finding for canonical issue '{issue_id}' not found.")
        host = request.target_host or finding.location.host or ""
        if host not in settings.sandbox_allowlist_set: raise ValidationRejected(f"Target host '{host}' is not in the configured lab allowlist.")
        cwes = [finding.vulnerability.cwe_primary, *finding.vulnerability.cwe_ids]
        expected = next((SCENARIOS[cwe] for cwe in cwes if cwe in SCENARIOS), None)
        scenario = (request.scenario or expected or "unknown").lower()
        if request.simulate_timeout: status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, "Lab simulation timed out before producing a result."
        elif scenario not in set(SCENARIOS.values()): status, confidence, summary = ValidationStatus.INCONCLUSIVE, 0.0, f"Unsupported lab scenario '{scenario}'."
        elif scenario == expected: status, confidence, summary = ValidationStatus.SIMULATED_MATCH, 0.75, f"Offline {scenario.upper()} fixture matched the finding classification."
        else: status, confidence, summary = ValidationStatus.SIMULATED_NO_MATCH, 0.6, f"Offline {scenario.upper()} fixture did not match the finding classification."
        now, validation_id = datetime.now(timezone.utc), f"val-{uuid.uuid4()}"
        content = redact_secrets(json.dumps({"simulation": True, "scenario": scenario, "target_host": host, "finding_id": finding.finding_id, "status": status.value, "summary": summary, "source_excerpt": finding.evidence.summary or ""}, sort_keys=True)) or ""
        retained = content.encode("utf-8")
        artifact = Artifact(artifact_id=f"art-{uuid.uuid4()}", validation_id=validation_id, artifact_type="validation_summary", content=content, content_hash=hashlib.sha256(retained).hexdigest(), content_size=len(retained), metadata={"simulation": True, "content_type": "application/json"}, created_at=now)
        result = ValidationResult(validation_id=validation_id, canonical_issue_id=issue_id, finding_id=finding.finding_id, status=status, confidence=confidence, sandbox_mode=request.mode, scenario=scenario, target_host=host, execution_summary=summary, limitations=[LIMITATION], executed_at=now, timeout_seconds=settings.sandbox_timeout_seconds, artifact_ids=[artifact.artifact_id], created_at=now)
        validation_repo.save(result, [artifact])
        return result

sandbox_service = SandboxService()
