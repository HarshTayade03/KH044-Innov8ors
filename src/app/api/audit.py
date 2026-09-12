"""Global audit-log inspection endpoints."""
from fastapi import APIRouter, Query

from src.app.repositories.audit_repo import audit_repo
from src.app.schemas.case import AuditEvent

router = APIRouter(tags=["Audit"])


@router.get("/audit-events", response_model=dict)
async def list_audit_events(
    entity_type: str | None = Query(default=None, min_length=1),
    actor: str | None = Query(default=None, min_length=1),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List immutable audit events across findings, issues, validations, and cases."""
    events, total = audit_repo.list(entity_type, actor, limit, offset)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [event.model_dump() for event in events],
    }
