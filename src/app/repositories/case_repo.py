"""Persistence for assembled cases, review decisions and audit history."""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from src.app.database import get_db, transaction
from src.app.schemas.case import (
    AuditEvent,
    Case,
    CaseDetail,
    CaseStatus,
    ReviewActionType,
    ReviewRecord,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CaseRepository:
    transaction = staticmethod(transaction)

    def get(self, case_id: str) -> Optional[Case]:
        with get_db() as db:
            row = db.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        return self._case(row) if row else None

    def get_for_issue(self, issue_id: str) -> Optional[Case]:
        with get_db() as db:
            row = db.execute("SELECT * FROM cases WHERE canonical_issue_id = ?", (issue_id,)).fetchone()
        return self._case(row) if row else None

    def list(self, limit: int = 100, offset: int = 0, status: Optional[CaseStatus] = None) -> list[Case]:
        query = "SELECT * FROM cases"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status.value)
        query += " ORDER BY last_updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with get_db() as db:
            rows = db.execute(query, params).fetchall()
        return [self._case(row) for row in rows]

    def save(self, case: Case) -> None:
        with get_db() as db:
            db.execute(
                """INSERT INTO cases
                (case_id, canonical_issue_id, status, title, summary, case_data,
                 created_at, last_updated_at, updated_at, stale)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(canonical_issue_id) DO UPDATE SET
                  case_id=excluded.case_id, status=excluded.status, title=excluded.title,
                  summary=excluded.summary, case_data=excluded.case_data,
                  last_updated_at=excluded.last_updated_at, updated_at=excluded.updated_at,
                  stale=excluded.stale""",
                (case.case_id, case.canonical_issue_id, case.status.value, case.title,
                 case.summary, json.dumps(case.case_data, default=str), case.created_at.isoformat(),
                 case.last_updated_at.isoformat(), case.updated_at.isoformat(), int(case.stale)),
            )

    def update_review(self, case: Case, review: ReviewRecord, audit: AuditEvent) -> None:
        with transaction() as db:
            db.execute(
                     """UPDATE cases SET status=?, case_data=?, last_updated_at=?, updated_at=?, stale=?
                   WHERE case_id=? AND status=? AND stale=0""",
                     (case.status.value, json.dumps(case.case_data, default=str), case.last_updated_at.isoformat(),
                      case.updated_at.isoformat(), int(case.stale), case.case_id, review.previous_status.value),
            )
            if db.execute("SELECT changes() AS n").fetchone()["n"] != 1:
                raise ValueError("Case changed before this review could be applied")
            if review.action == ReviewActionType.PRIORITY_OVERRIDE:
                db.execute(
                    "UPDATE priorities SET remediation_tier=?, updated_at=? WHERE canonical_issue_id=?",
                    (audit.details["new_tier"], review.reviewed_at.isoformat(), case.canonical_issue_id),
                )
            now = review.reviewed_at.isoformat()
            db.execute(
                """INSERT INTO reviews
                (review_id, case_id, action, actor_id, comment, reason, previous_status,
                 new_status, reviewed_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (review.review_id, review.case_id, review.action.value, review.actor_id,
                 review.comment, review.reason,
                 review.previous_status.value if review.previous_status else None,
                 review.new_status.value if review.new_status else None, now, now, now),
            )
            db.execute(
                """INSERT INTO audit_events
                (event_id, entity_type, entity_id, action, actor, details, occurred_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (audit.event_id, audit.entity_type, audit.entity_id, audit.action, audit.actor,
                 json.dumps(audit.details, default=str), audit.occurred_at.isoformat(), audit.occurred_at.isoformat()),
            )

    def audit(self, event: AuditEvent) -> None:
        with get_db() as db:
            db.execute(
                """INSERT INTO audit_events
                (event_id, entity_type, entity_id, action, actor, details, occurred_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.event_id, event.entity_type, event.entity_id, event.action, event.actor,
                 json.dumps(event.details, default=str), event.occurred_at.isoformat(), event.occurred_at.isoformat()),
            )

    def detail(self, case_id: str) -> Optional[CaseDetail]:
        case = self.get(case_id)
        if not case:
            return None
        with get_db() as db:
            reviews = db.execute("SELECT * FROM reviews WHERE case_id=? ORDER BY reviewed_at", (case_id,)).fetchall()
            events = db.execute(
                "SELECT * FROM audit_events WHERE entity_type='case' AND entity_id=? ORDER BY occurred_at",
                (case_id,),
            ).fetchall()
        return CaseDetail(
            **case.model_dump(),
            reviews=[ReviewRecord(
                review_id=row["review_id"], case_id=row["case_id"], action=ReviewActionType(row["action"]),
                actor_id=row["actor_id"], comment=row["comment"], reason=row["reason"],
                previous_status=CaseStatus(row["previous_status"]) if row["previous_status"] else None,
                new_status=CaseStatus(row["new_status"]) if row["new_status"] else None,
                reviewed_at=datetime.fromisoformat(row["reviewed_at"]),
            ) for row in reviews],
            audit_events=[AuditEvent(
                event_id=row["event_id"], entity_type=row["entity_type"], entity_id=row["entity_id"],
                action=row["action"], actor=row["actor"], details=json.loads(row["details"]),
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
            ) for row in events],
        )

    @staticmethod
    def _case(row) -> Case:
        return Case(
            case_id=row["case_id"], canonical_issue_id=row["canonical_issue_id"],
            status=CaseStatus(row["status"]), title=row["title"], summary=row["summary"],
            case_data=json.loads(row["case_data"]), stale=bool(row["stale"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_updated_at=datetime.fromisoformat(row["last_updated_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )


case_repo = CaseRepository()