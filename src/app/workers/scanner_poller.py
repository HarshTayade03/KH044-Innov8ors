"""
workers/scanner_poller.py — Autonomous scanner API polling worker.
FUTURE SCOPE STUB — Not implemented in prototype.

When implemented, this worker will:
1. Poll Nessus/Burp/ZAP scanner APIs on a schedule
2. Fetch new findings automatically (no manual upload required)
3. Forward findings to the ingestion pipeline

For the prototype, all ingestion is manual (file upload or form entry).
"""

# TODO [FS-03]: Implement scheduled scanner API polling
# Dependencies needed: celery or apscheduler, scanner API credentials


def poll_scanners():
    """
    STUB: Poll all configured scanner APIs for new findings.
    Future scope — not implemented in prototype.
    """
    # TODO [FS-03]: Implement this
    raise NotImplementedError("Autonomous scanner polling is future scope. Use manual upload for prototype.")
