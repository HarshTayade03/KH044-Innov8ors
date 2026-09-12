"""
services/notifier.py — Integration Hub and Notification Service.

Handles outbound alert dispatches (Slack, Teams, Webhooks), inbound scanner payload processing,
and formatted ticket exports for Jira and GitHub Issues.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.app.config import settings
from src.app.schemas.integration import (
    OutboundWebhookResult,
    TicketExportResponse,
    IntegrationStatus,
)

logger = logging.getLogger(__name__)


class IntegrationNotifierService:
    """Service for external integrations, outbound alerts, and ticket exports."""

    def dispatch_outbound_webhook(
        self, target_url: str, event_type: str, payload: Dict[str, Any]
    ) -> OutboundWebhookResult:
        """
        Dispatch an HTTP POST webhook alert to a target URL (Slack, Teams, or HTTP sink).
        """
        now_str = datetime.now(timezone.utc).isoformat()

        # Build Discord / Slack compatible structure based on target URL
        if "discord.com/api/webhooks" in target_url.lower():
            body = {
                "username": "VulnTriager AI Agent",
                "embeds": [
                    {
                        "title": f"🚨 {payload.get('title', 'Vulnerability Alert')}",
                        "description": payload.get("summary", "Security issue requires triage."),
                        "color": 14742088 if payload.get("risk_score", 0) >= 80 else 16109323,
                        "fields": [
                            {"name": "Risk Score", "value": f"{payload.get('risk_score', 'N/A')}/100", "inline": True},
                            {"name": "CWE", "value": str(payload.get("cwe_primary", "N/A")), "inline": True},
                            {"name": "Remediation Tier", "value": str(payload.get("remediation_tier", "Standard")), "inline": True},
                        ],
                        "footer": {"text": "AI-Assisted Vulnerability Triage Platform"},
                    }
                ],
            }
        elif "hooks.slack.com" in target_url.lower():
            body = {
                "text": f"🚨 *VulnTriager Alert: {event_type}*",
                "attachments": [
                    {
                        "color": "#e11d48" if payload.get("risk_score", 0) >= 80 else "#f59e0b",
                        "title": payload.get("title", "Vulnerability Alert"),
                        "text": payload.get("summary", "New security case requires triage."),
                        "fields": [
                            {"title": "Risk Score", "value": str(payload.get("risk_score", "N/A")), "short": True},
                            {"title": "CWE", "value": str(payload.get("cwe_primary", "N/A")), "short": True},
                            {"title": "Remediation Tier", "value": str(payload.get("remediation_tier", "Standard")), "short": True},
                        ],
                    }
                ],
            }
        else:
            body = {
                "event": event_type,
                "timestamp": now_str,
                "data": payload,
            }

        req_data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            target_url,
            data=req_data,
            headers={"Content-Type": "application/json", "User-Agent": "VulnTriager-Notifier/1.0"},
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status_code = resp.getcode()
                return OutboundWebhookResult(
                    success=200 <= status_code < 300,
                    status_code=status_code,
                    delivered_at=now_str,
                    message=f"Webhook delivered successfully (HTTP {status_code}).",
                )
        except urllib.error.HTTPError as e:
            return OutboundWebhookResult(
                success=False,
                status_code=e.code,
                delivered_at=now_str,
                message=f"HTTP Error {e.code}: {e.reason}",
            )
        except Exception as e:
            return OutboundWebhookResult(
                success=False,
                status_code=0,
                delivered_at=now_str,
                message=f"Delivery failed: {str(e)}",
            )

    def export_case_ticket(
        self,
        case_id: str,
        title: str,
        cwe_primary: str,
        risk_score: float,
        remediation_tier: str,
        findings_count: int,
        description: str,
        location: str,
        format_type: str = "jira",
    ) -> TicketExportResponse:
        """
        Generate ready-to-use markdown ticket body for Jira or GitHub Issues.
        """
        fmt = format_type.lower()
        tier_label = remediation_tier.upper()
        prio_map = {"IMMEDIATE": "Highest", "ACCELERATED": "High", "STANDARD": "Medium"}
        jira_priority = prio_map.get(tier_label, "Medium")

        if fmt == "jira":
            ticket_title = f"[{tier_label}] {title} ({cwe_primary})"
            body = (
                f"h2. Vulnerability Details\n"
                f"* *Case ID:* `{case_id}`\n"
                f"* *CWE Identifier:* `{cwe_primary}`\n"
                f"* *Composite Risk Score:* *{risk_score}/100* ({tier_label})\n"
                f"* *Findings Count:* {findings_count}\n\n"
                f"h3. Location & Description\n"
                f"*Location:* `{location}`\n\n"
                f"{description}\n\n"
                f"h3. Recommended Action\n"
                f"Triage and apply security remediation patch as specified by VulnTriager platform.\n"
            )
        else:  # github
            ticket_title = f"[{tier_label}] {title} ({cwe_primary})"
            body = (
                f"## 🚨 Security Vulnerability Report: {title}\n\n"
                f"| Attribute | Value |\n"
                f"| --- | --- |\n"
                f"| **Case ID** | `{case_id}` |\n"
                f"| **CWE ID** | `{cwe_primary}` |\n"
                f"| **Risk Score** | **{risk_score}/100** ({tier_label}) |\n"
                f"| **Correlated Findings** | {findings_count} |\n\n"
                f"### 📍 Affected Location\n`{location}`\n\n"
                f"### 📝 Description\n{description}\n\n"
                f"---\n*Report generated automatically by AI-Assisted Vulnerability Triage Platform.*"
            )

        return TicketExportResponse(
            case_id=case_id,
            format_type=fmt,
            ticket_title=ticket_title,
            ticket_body_markdown=body,
            labels=["security", f"cwe-{cwe_primary.lower().replace('cwe-', '')}", tier_label.lower()],
            priority_level=jira_priority,
        )

    def get_integration_status() -> IntegrationStatus:
        """Return operational status of external integration sinks."""
        slack_conf = bool(getattr(settings, "slack_webhook_url", None))
        return IntegrationStatus(
            inbound_webhook_enabled=True,
            outbound_slack_configured=slack_conf,
            supported_export_formats=["jira", "github", "json"],
        )
