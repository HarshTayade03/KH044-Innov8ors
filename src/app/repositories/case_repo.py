"""Persistence for case snapshots, reviews and immutable audit events."""
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from src.app.database import get_db, transaction
from src.app.schemas.case import AuditEvent, Case, CaseStatus, Review


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


class CaseRepository:
    transaction = staticmethod(transaction)

    def _case(self, row, db) -> Case:
        reviews = db.execute(
            "SELECT * FROM reviews WHERE case_id=? ORDER BY reviewed_at", (row["case_id"],)
        ).fetchall()
        audits = db.execute(
            "SELECT * FROM audit_events WHERE entity_type='case' AND entity_id=? ORDER BY occurred_at",
            (row["case_id"],),
        ).fetchall()
        return Case(
            case_id=row["case_id"], canonical_issue_id=row["canonical_issue_id"],
            status=CaseStatus(row["status"]), stale=bool(row["stale"]),
            title=row["title"], summary=row["summary"],
            case_data=json.loads(row["case_data"]),
            created_at=_dt(row["created_at"]), last_updated_at=_dt(row["last_updated_at"]),
            reviews=[Review(review_id=r["review_id"], case_id=r["case_id"],
                            action=r["action"], actor_id=r["actor_id"],
                            reason=r["reason"] or r["comment"] or "",
                            previous_status=CaseStatus(r["previous_status"]) if r["previous_status"] else None,
                            new_status=CaseStatus(r["new_status"]) if r["new_status"] else None,
                            reviewed_at=_dt(r["reviewed_at"])) for r in reviews],
            audit_events=[AuditEvent(event_id=a["event_id"], entity_type=a["entity_type"],
                                     entity_id=a["entity_id"], action=a["action"], actor=a["actor"],
                                     details=json.loads(a["details"]), occurred_at=_dt(a["occurred_at"]))
                          for a in audits],
        )

    def get(self, case_id: str) -> Case | None:
        with get_db() as db:
            row = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            return self._case(row, db) if row else None

    def get_for_issue(self, issue_id: str) -> Case | None:
        with get_db() as db:
            row = db.execute("SELECT * FROM cases WHERE canonical_issue_id=?", (issue_id,)).fetchone()
            return self._case(row, db) if row else None

    def list(self, status: CaseStatus | None = None, limit: int = 100, offset: int = 0) -> list[Case]:
        with get_db() as db:
            if status:
                rows = db.execute("SELECT * FROM cases WHERE status=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                                  (status.value, limit, offset)).fetchall()
            else:
                rows = db.execute("SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?",
                                  (limit, offset)).fetchall()
            return [self._case(row, db) for row in rows]

    def save_snapshot(self, case: Case) -> None:
        with get_db() as db:
            db.execute(
                """INSERT INTO cases (case_id, canonical_issue_id, status, title, summary, case_data,
                   created_at, last_updated_at, updated_at, stale) VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(case_id) DO UPDATE SET title=excluded.title, summary=excluded.summary,
                   case_data=excluded.case_data, last_updated_at=excluded.last_updated_at,
                   updated_at=excluded.updated_at, stale=excluded.stale""",
                (case.case_id, case.canonical_issue_id, case.status.value, case.title, case.summary,
                 json.dumps(case.case_data, default=str), case.created_at.isoformat(),
                 case.last_updated_at.isoformat(), case.last_updated_at.isoformat(), int(case.stale)),
            )

    def create_review(self, db, case_id: str, action: str, actor: str, reason: str,
                      previous: CaseStatus, new: CaseStatus | None) -> Review:
        now = datetime.now(timezone.utc)
        review = Review(review_id=str(uuid.uuid4()), case_id=case_id, action=action,
                        actor_id=actor, reason=reason, previous_status=previous,
                        new_status=new, reviewed_at=now)
        db.execute(
            """INSERT INTO reviews (review_id,case_id,action,actor_id,comment,reason,
               previous_status,new_status,reviewed_at,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (review.review_id, case_id, action, actor, reason, reason,
             previous.value, new.value if new else None, now.isoformat(), now.isoformat(), now.isoformat()),
        )
        return review

    def append_audit(self, db, case_id: str, action: str, actor: str, details: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """INSERT INTO audit_events
               (event_id,entity_type,entity_id,action,actor,details,occurred_at,created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), "case", case_id, action, actor, json.dumps(details),
             now, now),
        )


case_repo = CaseRepository()
