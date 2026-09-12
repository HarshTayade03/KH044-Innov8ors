from datetime import datetime, timezone

from src.app.database import get_db
from src.app.repositories.audit_repo import audit_repo


def test_global_audit_log_is_filterable_and_paginated():
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO audit_events
               (event_id, entity_type, entity_id, action, actor, details, occurred_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("audit-global-1", "finding", "finding-1", "imported", "analyst-1",
             '{"source":"burp"}', now, now),
        )
        db.execute(
            """INSERT INTO audit_events
               (event_id, entity_type, entity_id, action, actor, details, occurred_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("audit-global-2", "case", "case-1", "approved", "analyst-2",
             '{"reason":"verified"}', now, now),
        )

    events, total = audit_repo.list(entity_type="case", limit=1)
    assert total == 1
    assert events[0].action == "approved"
    assert events[0].actor == "analyst-2"
