"""Read access to the append-only cross-entity audit log."""
import json

from src.app.database import get_db
from src.app.schemas.case import AuditEvent


class AuditRepository:
    def list(self, entity_type=None, actor=None, limit=100, offset=0):
        clauses = []
        values = []
        if entity_type:
            clauses.append("entity_type=?")
            values.append(entity_type)
        if actor:
            clauses.append("actor=?")
            values.append(actor)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with get_db() as db:
            rows = db.execute(
                f"""SELECT * FROM audit_events {where}
                    ORDER BY occurred_at DESC LIMIT ? OFFSET ?""",
                (*values, limit, offset),
            ).fetchall()
            total = db.execute(
                f"SELECT COUNT(*) AS count FROM audit_events {where}",
                tuple(values),
            ).fetchone()["count"]
        return [self._event(row) for row in rows], total

    @staticmethod
    def _event(row):
        return AuditEvent(
            event_id=row["event_id"],
            entity_type=row["entity_type"],
            entity_id=row["entity_id"],
            action=row["action"],
            actor=row["actor"],
            details=json.loads(row["details"]),
            occurred_at=row["occurred_at"],
        )


audit_repo = AuditRepository()
