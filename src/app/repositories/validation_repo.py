"""Persistence for append-only validation runs and evidence artifacts."""
import json
from datetime import datetime
from src.app.database import get_db
from src.app.schemas.validation import Artifact, SandboxMode, ValidationResult, ValidationStatus

class ValidationRepository:
    def save(self, result: ValidationResult, artifacts: list[Artifact]) -> None:
        with get_db() as db:
            db.execute("""INSERT INTO validation_runs (validation_id, canonical_issue_id, finding_id, status, confidence, sandbox_mode, execution_summary, executed_at, timeout_seconds, created_at, updated_at, scenario, target_host, limitations) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (result.validation_id, result.canonical_issue_id, result.finding_id, result.status.value, result.confidence, result.sandbox_mode.value, result.execution_summary, result.executed_at.isoformat(), result.timeout_seconds, result.created_at.isoformat(), result.created_at.isoformat(), result.scenario, result.target_host, json.dumps(result.limitations)))
            for a in artifacts:
                db.execute("""INSERT INTO artifacts (artifact_id, entity_type, entity_id, artifact_type, content, content_hash, content_size, redacted, metadata, created_at, updated_at) VALUES (?, 'validation', ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (a.artifact_id, result.validation_id, a.artifact_type, a.content, a.content_hash, a.content_size, int(a.redacted), json.dumps(a.metadata), a.created_at.isoformat(), a.created_at.isoformat()))

    def get(self, validation_id: str) -> ValidationResult | None:
        with get_db() as db:
            r = db.execute("SELECT * FROM validation_runs WHERE validation_id=?", (validation_id,)).fetchone()
            if not r: return None
            ids = [x["artifact_id"] for x in db.execute("SELECT artifact_id FROM artifacts WHERE entity_type='validation' AND entity_id=? ORDER BY created_at", (validation_id,)).fetchall()]
        return ValidationResult(validation_id=r["validation_id"], canonical_issue_id=r["canonical_issue_id"], finding_id=r["finding_id"], status=ValidationStatus(r["status"]), confidence=r["confidence"], sandbox_mode=SandboxMode(r["sandbox_mode"]), scenario=r["scenario"], target_host=r["target_host"], execution_summary=r["execution_summary"], limitations=json.loads(r["limitations"]), executed_at=datetime.fromisoformat(r["executed_at"]), timeout_seconds=r["timeout_seconds"], artifact_ids=ids, created_at=datetime.fromisoformat(r["created_at"]))

    def list_artifacts(self, validation_id: str) -> list[Artifact]:
        with get_db() as db:
            rows = db.execute("SELECT * FROM artifacts WHERE entity_type='validation' AND entity_id=? ORDER BY created_at", (validation_id,)).fetchall()
        return [Artifact(artifact_id=r["artifact_id"], validation_id=validation_id, artifact_type=r["artifact_type"], content=r["content"], content_hash=r["content_hash"], content_size=r["content_size"], redacted=bool(r["redacted"]), metadata=json.loads(r["metadata"]), created_at=datetime.fromisoformat(r["created_at"])) for r in rows]

    def latest_for_issue(self, issue_id: str) -> ValidationResult | None:
        with get_db() as db:
            r = db.execute("SELECT validation_id FROM validation_runs WHERE canonical_issue_id=? ORDER BY created_at DESC LIMIT 1", (issue_id,)).fetchone()
        return self.get(r["validation_id"]) if r else None

validation_repo = ValidationRepository()
