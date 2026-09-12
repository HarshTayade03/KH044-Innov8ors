"""Read persisted demo batch membership; callers serialize import transactions."""
from src.app.database import get_db


def batch_finding_ids(batch_id: str) -> list[str]:
    with get_db() as db:
        rows = db.execute(
            "SELECT finding_id FROM scanner_findings WHERE ingestion_batch_id=? ORDER BY rowid",
            (batch_id,),
        ).fetchall()
    return [row['finding_id'] for row in rows]
