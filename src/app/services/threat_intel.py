"""Threat-feed enrichment with explicit local/live provenance and freshness."""
import hashlib
import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from datetime import datetime, timezone
from pathlib import Path

from src.app.config import settings
from src.app.repositories.threat_intel_repo import threat_intel_repo
from src.app.schemas.risk import ThreatEnrichment, ThreatFeedStatus
from pydantic import ValidationError


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
        except (OSError, ValueError, TypeError, KeyError, AttributeError, ValidationError) as exc:
            raise ThreatIntelUnavailable(f'Mock threat feed unavailable or malformed: {exc}') from exc
        threat_intel_repo.save(enrichment)
        return enrichment

    def feed_status(self):
        now = datetime.now(timezone.utc)
        return [
            ThreatFeedStatus(
                name="CISA KEV",
                provider="Cybersecurity and Infrastructure Security Agency",
                endpoint=settings.cisa_kev_url,
                mode="live" if settings.kev_live else "local_mock",
                available=Path(settings.kev_data_path).exists() if not settings.kev_live else settings.threat_feed_refresh_enabled,
                last_checked_at=now,
                note="Known exploited vulnerabilities catalog; local mock is used unless live mode is explicitly enabled.",
            ),
            ThreatFeedStatus(
                name="NIST NVD",
                provider="National Vulnerability Database",
                endpoint=settings.nvd_api_url,
                mode="live" if settings.threat_feed_refresh_enabled else "configured",
                available=bool(settings.nvd_api_url),
                last_checked_at=now,
                note="CVE descriptions, CVSS metrics, and references are fetched per CVE only during an explicit refresh.",
            ),
            ThreatFeedStatus(
                name="FIRST EPSS",
                provider="FIRST.org",
                endpoint=settings.epss_api_url,
                mode="live" if settings.epss_live else "local_mock",
                available=Path(settings.epss_data_path).exists() if not settings.epss_live else settings.threat_feed_refresh_enabled,
                last_checked_at=now,
                note="Exploit prediction probability and percentile; local mock is the deterministic default.",
            ),
        ]

    def fetch_live_cve(self, cve_id):
        """Fetch one CVE from configured public feeds when explicitly enabled."""
        if not settings.threat_feed_refresh_enabled:
            raise ThreatIntelUnavailable("Live feed refresh is disabled. Enable THREAT_FEED_REFRESH_ENABLED explicitly.")
        cve_id = cve_id.strip().upper()
        headers = {"User-Agent": f"{settings.app_name}/{settings.app_version}"}
        try:
            nvd_url = f"{settings.nvd_api_url}?{urlencode({'cveId': cve_id})}"
            with urlopen(Request(nvd_url, headers=headers), timeout=15) as response:
                nvd_payload = json.loads(response.read())
            epss_url = f"{settings.epss_api_url}?{urlencode({'cve': cve_id})}"
            with urlopen(Request(epss_url, headers=headers), timeout=15) as response:
                epss_payload = json.loads(response.read())
            with urlopen(Request(settings.cisa_kev_url, headers=headers), timeout=15) as response:
                kev_payload = json.loads(response.read())
        except Exception as exc:
            raise ThreatIntelUnavailable(f"Live threat feed request failed: {exc}") from exc
        nvd_bytes = json.dumps(nvd_payload, sort_keys=True).encode()
        epss_bytes = json.dumps(epss_payload, sort_keys=True).encode()
        epss_item = (epss_payload.get("data") or [{}])[0]
        kev_item = next(
            (item for item in kev_payload.get("vulnerabilities", [])
             if str(item.get("cveID", "")).upper() == cve_id),
            None,
        )
        return {
            "cve_id": cve_id,
            "kev_flag": kev_item is not None,
            "kev_date_added": kev_item.get("dateAdded") if kev_item else None,
            "nist": {
                "vulnerabilities": len(nvd_payload.get("vulnerabilities", [])),
                "source_fingerprint": hashlib.sha256(nvd_bytes).hexdigest(),
            },
            "epss_score": float(epss_item.get("epss", 0.0)),
            "epss_percentile": float(epss_item.get("percentile", 0.0)),
            "source_fingerprint": hashlib.sha256(nvd_bytes + b":" + epss_bytes).hexdigest(),
            "fetched_at": datetime.now(timezone.utc),
        }


threat_intel_service = ThreatIntelService()
