"""
services/threat_intel.py — Threat intelligence lookup (CISA KEV + FIRST.org EPSS).

Defined according to docs/MODULE_SPECS/M4_threat_intel_prioritization.md.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from src.app.config import settings
from src.app.database import get_db
from src.app.schemas.risk import ThreatEnrichment


class ThreatIntelService:
    """Service for enriching vulnerabilities with CISA KEV and EPSS threat intelligence."""

    def __init__(self):
        self._kev_mock_cache: Optional[dict[str, dict]] = None
        self._epss_mock_cache: Optional[dict[str, dict]] = None

    def _load_kev_mock(self) -> dict[str, dict]:
        if self._kev_mock_cache is None:
            self._kev_mock_cache = {}
            if os.path.exists(settings.kev_data_path):
                try:
                    with open(settings.kev_data_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data.get("vulnerabilities", []):
                            cve = item.get("cveID")
                            if cve:
                                self._kev_mock_cache[cve.upper()] = item
                except Exception as e:
                    print(f"[threat_intel] Error loading KEV mock: {e}")
        return self._kev_mock_cache

    def _load_epss_mock(self) -> dict[str, dict]:
        if self._epss_mock_cache is None:
            self._epss_mock_cache = {}
            if os.path.exists(settings.epss_data_path):
                try:
                    with open(settings.epss_data_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data.get("data", []):
                            cve = item.get("cve")
                            if cve:
                                self._epss_mock_cache[cve.upper()] = item
                except Exception as e:
                    print(f"[threat_intel] Error loading EPSS mock: {e}")
        return self._epss_mock_cache

    def _get_from_db(self, cve_id: str) -> Optional[ThreatEnrichment]:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM threat_intelligence WHERE cve_id = ?",
                (cve_id.upper(),)
            ).fetchone()

        if not row:
            return None

        return ThreatEnrichment(
            cve_id=row["cve_id"],
            kev_flag=bool(row["kev_flag"]),
            kev_date_added=row["kev_date_added"],
            epss_score=row["epss_score"] or 0.0,
            epss_percentile=row["epss_percentile"] or 0.0,
            data_source=row["data_source"]
        )

    def _save_to_db(self, enrichment: ThreatEnrichment) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        with get_db() as db:
            db.execute(
                """
                INSERT INTO threat_intelligence (
                    cve_id, kev_flag, kev_date_added, epss_score, epss_percentile,
                    data_source, fetched_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    kev_flag=excluded.kev_flag,
                    kev_date_added=excluded.kev_date_added,
                    epss_score=excluded.epss_score,
                    epss_percentile=excluded.epss_percentile,
                    data_source=excluded.data_source,
                    fetched_at=excluded.fetched_at,
                    updated_at=excluded.updated_at
                """,
                (
                    enrichment.cve_id.upper(),
                    1 if enrichment.kev_flag else 0,
                    enrichment.kev_date_added,
                    enrichment.epss_score,
                    enrichment.epss_percentile,
                    enrichment.data_source,
                    now_str,
                    now_str,
                    now_str,
                )
            )

    def enrich_cve(self, cve_id: str) -> ThreatEnrichment:
        """
        Enrich a single CVE ID with KEV and EPSS data (checks DB cache -> mock -> live).
        """
        cve_upper = cve_id.strip().upper()

        # Check DB cache first
        cached = self._get_from_db(cve_upper)
        if cached:
            return cached

        kev_map = self._load_kev_mock()
        epss_map = self._load_epss_mock()

        kev_item = kev_map.get(cve_upper)
        epss_item = epss_map.get(cve_upper)

        kev_flag = bool(kev_item)
        kev_date = kev_item.get("dateAdded") if kev_item else None

        epss_score = 0.0
        epss_percentile = 0.0
        if epss_item:
            try:
                epss_score = float(epss_item.get("epss", 0.0))
                epss_percentile = float(epss_item.get("percentile", 0.0))
            except (ValueError, TypeError):
                pass

        enrichment = ThreatEnrichment(
            cve_id=cve_upper,
            kev_flag=kev_flag,
            kev_date_added=kev_date,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            data_source="mock"
        )

        self._save_to_db(enrichment)
        return enrichment


threat_intel_service = ThreatIntelService()
