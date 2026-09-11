"""Persistence for case snapshots, reviews, and immutable audit events."""
import json
import uuid
from datetime import datetime, timezone
from src.app.database import get_db
from src.app.schemas.case import Case, CaseStatus, Review, ReviewAction, AuditEvent

def _dt(value): return datetime.fromisoformat(value)

class CaseRepository:
    def _case(self, row):
        return Case(case_id=row["case_id"], canonical_issue_id=row["canonical_issue_id"],
                    status=CaseStatus(row["status"]), title=row["title"], summary=row["summary"],
                    stale=bool(row["stale"]), case_data=json.loads(row["case_data"]),
                    created_at=_dt(row["created_at"]), last_updated_at=_dt(row["last_updated_at"]))

    def get(self, case_id):
        with get_db() as db:
            row = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return self._case(row) if row else None

    def get_for_issue(self, issue_id):
        with get_db() as db:
            row = db.execute("SELECT * FROM cases WHERE canonical_issue_id=?", (issue_id,)).fetchone()
        return self._case(row) if row else None

    def list(self, status=None, limit=100, offset=0):
        with get_db() as db:
            if status:
                rows = db.execute("SELECT * FROM cases WHERE status=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (status, limit, offset)).fetchall()
            else:
                rows = db.execute("SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [self._case(r) for r in rows]

    def save(self, case: Case, db=None):
        own = db is None
        context = get_db() if own else None
        if own: db = context.__enter__()
        try:
            db.execute("""INSERT INTO cases(case_id,canonical_issue_id,status,title,summary,case_data,created_at,last_updated_at,updated_at,stale)
                VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(canonical_issue_id) DO UPDATE SET
                status=excluded.status,title=excluded.title,summary=excluded.summary,case_data=excluded.case_data,
                last_updated_at=excluded.last_updated_at,updated_at=excluded.updated_at,stale=excluded.stale""",
                (case.case_id, case.canonical_issue_id, case.status.value, case.title, case.summary,
                 json.dumps(case.case_data, default=str), case.created_at.isoformat(), case.last_updated_at.isoformat(),
                 case.last_updated_at.isoformat(), int(case.stale)))
        finally:
            if own: context.__exit__(None, None, None)

    def add_review(self, review: Review, db):
        db.execute("""INSERT INTO reviews(review_id,case_id,action,actor_id,comment,reason,previous_status,new_status,reviewed_at,created_at,updated_at)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                   (review.review_id, review.case_id, review.action.value, review.actor_id, review.reason,
                    review.reason, review.previous_status.value if review.previous_status else None,
                    review.new_status.value if review.new_status else None, review.reviewed_at.isoformat(),
                    review.reviewed_at.isoformat(), review.reviewed_at.isoformat()))

    def add_audit(self, event: AuditEvent, db):
        db.execute("INSERT INTO audit_events(event_id,entity_type,entity_id,action,actor,details,occurred_at,created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (event.event_id,event.entity_type,event.entity_id,event.action,event.actor,json.dumps(event.details,default=str),
                    event.occurred_at.isoformat(),event.occurred_at.isoformat()))

    def audits(self, case_id):
        with get_db() as db:
            rows=db.execute("SELECT * FROM audit_events WHERE entity_type='case' AND entity_id=? ORDER BY occurred_at", (case_id,)).fetchall()
        return [AuditEvent(event_id=r["event_id"],entity_type=r["entity_type"],entity_id=r["entity_id"],action=r["action"],
                           actor=r["actor"],details=json.loads(r["details"]),occurred_at=_dt(r["occurred_at"])) for r in rows]

    def reviews(self, case_id):
        """Return the review history in decision order for case inspection."""
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM reviews WHERE case_id=? ORDER BY reviewed_at, created_at",
                (case_id,),
            ).fetchall()
        return [
            Review(
                review_id=row["review_id"],
                case_id=row["case_id"],
                action=ReviewAction(row["action"]),
                actor_id=row["actor_id"],
                reason=row["reason"] or row["comment"] or "",
                previous_status=CaseStatus(row["previous_status"]) if row["previous_status"] else None,
                new_status=CaseStatus(row["new_status"]) if row["new_status"] else None,
                reviewed_at=_dt(row["reviewed_at"]),
            )
            for row in rows
        ]

case_repo = CaseRepository()
