"""Threat-intelligence feed status and explicit refresh endpoints."""
from fastapi import APIRouter, HTTPException, Query

from src.app.services.threat_intel import ThreatIntelUnavailable, threat_intel_service

router = APIRouter(tags=["Threat Intelligence"])


@router.get("/threat-intelligence/feeds")
async def feed_status():
    return {"feeds": [feed.model_dump(mode="json") for feed in threat_intel_service.feed_status()]}


@router.post("/threat-intelligence/refresh")
async def refresh_cve(cve_id: str = Query(min_length=4)):
    try:
        return threat_intel_service.fetch_live_cve(cve_id)
    except ThreatIntelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
