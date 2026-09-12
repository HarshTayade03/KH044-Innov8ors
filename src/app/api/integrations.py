"""
API router for External Integrations, Inbound Webhooks, Outbound Alerts, and Ticket Exports.
"""

from fastapi import APIRouter, HTTPException, Query
from src.app.config import settings
from src.app.repositories.case_repo import case_repo
from src.app.schemas.integration import (
    InboundWebhookPayload,
    InboundWebhookResponse,
    IntegrationStatus,
    OutboundWebhookRequest,
    OutboundWebhookResult,
    TicketExportResponse,
)
from src.app.services.normalizer import normalizer_service
from src.app.services.notifier import IntegrationNotifierService

router = APIRouter(tags=["Integrations"])
notifier_service = IntegrationNotifierService()


@router.post("/settings/llm-key")
async def update_llm_key(api_key: str = Query(...), provider: str = Query("groq")):
    """
    Update runtime LLM API Key (Groq, OpenAI) to enable live LLM synthesis and patch generation.
    """
    settings.llm_api_key = api_key.strip()
    settings.llm_provider = provider.lower()
    settings.llm_enabled = True
    if settings.llm_provider == "groq" and (not settings.llm_model or settings.llm_model == "llama-3.3-70b-versatile"):
        settings.llm_model = "openai/gpt-oss-20b"
    return {
        "status": "updated",
        "provider": settings.llm_provider,
        "model": settings.llm_model,
        "llm_enabled": True,
    }


@router.get("/integrations/status", response_model=IntegrationStatus)
async def get_integrations_status():
    """Report status of external integration sinks."""
    return IntegrationNotifierService.get_integration_status()


@router.post("/integrations/webhook/ingest", response_model=InboundWebhookResponse)
async def ingest_webhook(payload: InboundWebhookPayload):
    """
    Ingest scanner finding payloads directly via continuous scanner webhooks.
    """
    if not payload.findings:
        raise HTTPException(status_code=400, detail="Inbound webhook payload contains no findings.")

    # Infer parser format or use sarif/direct json
    source = payload.source_name.lower()
    parser_type = "sarif" if "sarif" in source else "burp"

    summary = normalizer_service.normalize_batch(
        payload.findings,
        source_scanner=parser_type,
    )

    return InboundWebhookResponse(
        status="accepted",
        findings_processed=summary.normalized + summary.normalized_with_warnings,
        batch_id=summary.batch_id,
    )


@router.post("/integrations/test-webhook", response_model=OutboundWebhookResult)
async def test_outbound_webhook(request: OutboundWebhookRequest):
    """
    Dispatch a test alert payload to a target webhook endpoint (Slack, Teams, Custom).
    """
    return notifier_service.dispatch_outbound_webhook(
        target_url=request.target_url,
        event_type=request.event_type,
        payload=request.payload or {
            "title": "Test Security Alert",
            "summary": "This is a dry-run test alert from VulnTriager.",
            "risk_score": 85.0,
            "cwe_primary": "CWE-89",
            "remediation_tier": "Immediate",
        },
    )


@router.post("/cases/{case_id}/export-ticket", response_model=TicketExportResponse)
async def export_case_ticket(case_id: str, format_type: str = Query("jira", pattern="^(jira|github)$")):
    """
    Export case details formatted as a Markdown ticket for Jira or GitHub Issues.
    """
    case = case_repo.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    snap = case.case_data or {}
    cwe = snap.get("cwe_primary", "CWE-OTHER")
    title = snap.get("title", f"Security Case {case_id}")
    risk_score = float(snap.get("risk_score", 50.0))
    tier = snap.get("remediation_tier", "Standard")
    location = snap.get("canonical_path", "Unknown location")
    desc = snap.get("description", "No detailed description provided.")
    finding_ids = snap.get("source_finding_ids", [])

    return notifier_service.export_case_ticket(
        case_id=case_id,
        title=title,
        cwe_primary=cwe,
        risk_score=risk_score,
        remediation_tier=tier,
        findings_count=len(finding_ids) if isinstance(finding_ids, list) else 1,
        description=desc,
        location=location,
        format_type=format_type,
    )
