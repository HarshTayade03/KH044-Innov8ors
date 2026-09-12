"""
Pydantic schemas for Inbound Webhooks, Outbound Alerts, and Ticket Exports.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class InboundWebhookPayload(BaseModel):
    """Payload schema for inbound continuous scanner webhooks."""
    source_name: str = Field(..., description="Name of sending tool (e.g. github_actions, snyk_webhook, trivy_ci)")
    findings: List[Dict[str, Any]] = Field(..., description="Raw finding objects or SARIF results")
    repository: Optional[str] = Field(None, description="Repository or project name")
    branch: Optional[str] = Field(None, description="Git branch or environment tag")


class InboundWebhookResponse(BaseModel):
    """Response returned upon receiving an inbound scanner webhook."""
    status: str = Field("accepted", description="Ingestion acceptance status")
    findings_processed: int = Field(..., description="Number of findings successfully ingested")
    batch_id: str = Field(..., description="Generated batch ingestion ID")


class OutboundWebhookRequest(BaseModel):
    """Request DTO to dispatch or test an outbound alert webhook."""
    target_url: str = Field(..., description="Target webhook URL (Slack, Teams, or HTTP endpoint)")
    event_type: str = Field("case_created", description="Event type (case_created, high_risk_alert, test)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Custom payload dict to send")


class OutboundWebhookResult(BaseModel):
    """Result of an outbound webhook dispatch attempt."""
    success: bool = Field(..., description="True if target returned 2xx HTTP status")
    status_code: int = Field(..., description="HTTP response status code from target")
    delivered_at: str = Field(..., description="ISO 8601 delivery timestamp")
    message: str = Field(..., description="Delivery summary or error message")


class TicketExportResponse(BaseModel):
    """Formatted issue export payload for Jira or GitHub Issues."""
    case_id: str = Field(..., description="Case identifier")
    format_type: str = Field(..., description="jira or github")
    ticket_title: str = Field(..., description="Formatted ticket title")
    ticket_body_markdown: str = Field(..., description="Formatted markdown/Jira-markup ticket body")
    labels: List[str] = Field(default_factory=list, description="Recommended ticket tags/labels")
    priority_level: str = Field(..., description="Mapped ticket priority (Highest, High, Medium)")


class IntegrationStatus(BaseModel):
    """Overall status of external integration sinks."""
    inbound_webhook_enabled: bool = Field(True, description="Whether continuous webhook ingestion is ready")
    outbound_slack_configured: bool = Field(False, description="Whether Slack webhook URL is configured")
    supported_export_formats: List[str] = Field(["jira", "github", "json"], description="Supported export formats")
