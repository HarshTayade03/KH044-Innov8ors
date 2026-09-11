"""Content-addressed mock threat intelligence cache."""
from datetime import datetime, timezone

from src.app.database import get_db
from src.app.schemas.risk import ThreatEnrichment


class ThreatIntelRepository:
    def get(self, cve_id, fingerprint):
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM threat_intelligence WHERE cve_id=? AND data_source='mock' AND source_fingerprint=?",
                (cve_id, fingerprint),
            ).fetchone()
        if row is None:
            return None
        return ThreatEnrichment(
            cve_id=row['cve_id'], kev_flag=bool(row['kev_flag']), kev_date_added=row['kev_date_added'],
            epss_score=row['epss_score'], epss_percentile=row['epss_percentile'], data_source='mock',
            source_fingerprint=row['source_fingerprint'], fetched_at=row['fetched_at'],
        )

    def save(self, enrichment):
        now = datetime.now(timezone.utc).isoformat()
        with get_db() as db:
            db.execute('''
                INSERT INTO threat_intelligence (cve_id, kev_flag, kev_date_added, epss_score,
                    epss_percentile, data_source, fetched_at, source_fingerprint, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET kev_flag=excluded.kev_flag,
                    kev_date_added=excluded.kev_date_added, epss_score=excluded.epss_score,
                    epss_percentile=excluded.epss_percentile, data_source=excluded.data_source,
                    fetched_at=excluded.fetched_at, source_fingerprint=excluded.source_fingerprint,
                    updated_at=excluded.updated_at
            ''', (enrichment.cve_id, int(enrichment.kev_flag), enrichment.kev_date_added,
                  enrichment.epss_score, enrichment.epss_percentile, enrichment.data_source,
                  enrichment.fetched_at.isoformat(), enrichment.source_fingerprint, now, now))


threat_intel_repo = ThreatIntelRepository()
