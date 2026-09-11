"""
repositories/findings_repo.py — All database read/write operations.
STUB — Methods added progressively as each module is implemented.

Architecture rule: NO module talks to SQLite directly except this file.
All persistence goes through this repository.
"""

from src.app.database import get_db


class FindingsRepository:
    """Central data access layer. All modules use this to read/write the database."""
    # Module 1 will add: save_scanner_finding(), save_normalized_finding(), get_finding()
    # Module 2 will add: save_finding_views(), get_finding_views(), save_embeddings()
    # Module 3 will add: save_cluster(), get_clusters(), save_canonical_issue()
    # Module 4 will add: save_threat_intel(), save_priority(), get_priority()
    # Module 5 will add: save_validation_run(), save_artifact(), get_artifacts()
    # Module 6 will add: save_case(), get_case(), save_review(), save_audit_event()
    pass


# Module-level singleton — import this in all service modules
repo = FindingsRepository()
