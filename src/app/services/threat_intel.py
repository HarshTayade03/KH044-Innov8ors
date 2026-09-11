"""Mock KEV/EPSS enrichment with explicit provenance and content-based freshness."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from src.app.config import settings
from src.app.repositories.threat_intel_repo import threat_intel_repo
from src.app.schemas.risk import ThreatEnrichment


class ThreatIntelUnavailable(RuntimeError):
    pass


class ThreatIntelService:
    def __init__(self):
        self._kev_mock_cache = None
        self._epss_mock_cache = None

    def check_mode(self):
        if settings.kev_live or settings.epss_live:
            raise ThreatIntelUnavailable('Live KEV/EPSS fetching is not implemented; disable KEV_LIVE and EPSS_LIVE for mock mode')

    def enrich_cve(self, cve_id):
        self.check_mode()
        cve_id = cve_id.strip().upper()
        try:
            kev_bytes = Path(settings.kev_data_path).read_bytes()
            epss_bytes = Path(settings.epss_data_path).read_bytes()
            kev_data, epss_data = json.loads(kev_bytes), json.loads(epss_bytes)
            if not isinstance(kev_data.get('vulnerabilities'), list) or not isinstance(epss_data.get('data'), list):
                raise ValueError('Expected KEV vulnerabilities and EPSS data arrays')
            # Hash each file separately to avoid ambiguous concatenation.
            fingerprint = hashlib.sha256(kev_bytes).hexdigest() + ':' + hashlib.sha256(epss_bytes).hexdigest()
            cached = threat_intel_repo.get(cve_id, fingerprint)
            if cached:
                return cached
            kev = {item['cveID'].upper(): item for item in kev_data['vulnerabilities']}
            epss = {item['cve'].upper(): item for item in epss_data['data']}
            kev_item, epss_item = kev.get(cve_id), epss.get(cve_id, {})
            enrichment = ThreatEnrichment(
                cve_id=cve_id, kev_flag=kev_item is not None,
                kev_date_added=kev_item.get('dateAdded') if kev_item else None,
                epss_score=float(epss_item.get('epss', 0)),
                epss_percentile=float(epss_item.get('percentile', 0)),
                data_source='mock', source_fingerprint=fingerprint,
                fetched_at=datetime.now(timezone.utc),
            )
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ThreatIntelUnavailable(f'Mock threat feed unavailable or malformed: {exc}') from exc
        threat_intel_repo.save(enrichment)
        return enrichment


threat_intel_service = ThreatIntelService()
