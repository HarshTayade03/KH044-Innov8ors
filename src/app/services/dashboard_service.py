"""Dashboard read model and truthful provenance labels."""

from src.app.repositories.dashboard_repo import dashboard_repo


class DashboardService:
    def metrics(self) -> dict:
        counts = dashboard_repo.metrics()
        nonempty = any(value for key, value in counts.items() if key != "cases_by_status")
        return {
            "data_status": "available" if nonempty else "empty",
            "counts": counts,
            "simulation_labels": [
                "Threat intelligence rows are mock-feed data when present.",
                "Validation rows marked lab_simulator are simulated and do not prove exploitability.",
            ],
        }

    def queue(self, limit: int, offset: int, status: str | None = None) -> dict:
        cases, total = dashboard_repo.list_cases(limit, offset, status)
        return {
            "data_status": "available" if cases else "empty",
            "total": total, "limit": limit, "offset": offset, "cases": cases,
            "simulation_labels": ["Lab simulator validation is clearly labeled in case detail."],
        }


dashboard_service = DashboardService()
