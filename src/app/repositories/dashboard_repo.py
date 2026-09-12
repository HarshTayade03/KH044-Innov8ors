"""Read-only aggregate queries for analyst dashboard metrics."""

from src.app.database import get_db
from src.app.schemas.dashboard import DashboardMetrics


class DashboardRepository:
    def metrics(self) -> DashboardMetrics:
        with get_db() as db:
            count = lambda query: int(db.execute(query).fetchone()["count"])
            grouped = lambda query: {
                row["value"]: int(row["count"])
                for row in db.execute(query).fetchall()
            }

            return DashboardMetrics(
                findings=count("SELECT COUNT(*) AS count FROM normalized_findings"),
                active_issues=count(
                    "SELECT COUNT(*) AS count FROM canonical_issues WHERE active=1"
                ),
                clusters=count("SELECT COUNT(*) AS count FROM clusters"),
                validations=count("SELECT COUNT(*) AS count FROM validation_runs"),
                cases=count("SELECT COUNT(*) AS count FROM cases"),
                prioritized=count(
                    """
                    SELECT COUNT(*) AS count
                    FROM priorities p
                    JOIN canonical_issues c USING (canonical_issue_id)
                    WHERE c.active=1
                    """
                ),
                validation_statuses=grouped(
                    """
                    SELECT status AS value, COUNT(*) AS count
                    FROM validation_runs
                    GROUP BY status
                    """
                ),
                remediation_tiers=grouped(
                    """
                    SELECT remediation_tier AS value, COUNT(*) AS count
                    FROM priorities p
                    JOIN canonical_issues c USING (canonical_issue_id)
                    WHERE c.active=1
                    GROUP BY remediation_tier
                    """
                ),
                case_statuses=grouped(
                    "SELECT status AS value, COUNT(*) AS count FROM cases GROUP BY status"
                ),
                evidence_artifacts=count("SELECT COUNT(*) AS count FROM artifacts"),
                provenance={
                    "validation_mode": "offline_lab_simulator",
                    "threat_intelligence": "mock",
                    "real_exploitability_confirmed": False,
                },
            )


dashboard_repo = DashboardRepository()
