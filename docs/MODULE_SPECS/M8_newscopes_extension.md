# M8: New Scopes Extension — AI Auto-Remediation, Integrations, and Docker Sandbox

Updated: 2026-09-12. Branch: `feature/newscopes`.

## Overview & Scope

Module M8 extends the **AI-Assisted Vulnerability Triage Platform** with three lightweight, production-grade capabilities designed for rapid execution and high analyst value:

1. **AI Auto-Remediation & Patch Generator Agent**:
   - Generates contextual git unified diffs and code fix proposals for canonical vulnerability findings using LLM inference (or deterministic rules fallback).
   - Validates patch syntax and provides human analysts with an interactive side-by-side diff inspector and patch export.

2. **Autonomous Integration & Notification Hub**:
   - **Inbound Webhook Receiver**: `POST /api/v1/integrations/webhook/ingest` allows CI/CD tools, GitHub Actions, and external security scanners to stream findings directly into the ingestion pipeline.
   - **Outbound Webhook Dispatcher**: Asynchronously dispatches formatted JSON/Slack alerts when `Immediate` cases are created or reviewed. Includes `POST /api/v1/integrations/test-webhook` for dry-run verification.
   - **Jira & GitHub Ticket Exporter**: Generates formatted ticket payloads and markdown snippets (`POST /api/v1/cases/{id}/export-ticket`).

3. **Small-Scale Ephemeral Docker Sandbox Validation**:
   - Inspects Docker host availability (`is_docker_available()`).
   - When Docker is present and `DOCKER_SANDBOX_ENABLED=true`, spawns short-lived isolated containers (with `network_mode="none"`, 64MB memory limit, 5-second timeout) to execute safe validation probes.
   - If Docker is disabled or host is unavailable, returns typed status (`docker_unavailable`, `disabled_by_policy`) with clear diagnostic guidance and graceful fallback.

---

## API Contracts

### 1. AI Auto-Remediation (`src/app/api/remediation.py`)
- `POST /api/v1/canonical-issues/{canonical_issue_id}/remediation-patch`: Generates a structured remediation patch proposal containing git diff, explanation, security recommendation, and syntax validation status.
- `GET /api/v1/remediations/{canonical_issue_id}`: Retrieves cached or previously generated remediation proposals for a canonical issue.

### 2. Integrations Hub (`src/app/api/integrations.py`)
- `POST /api/v1/integrations/webhook/ingest`: Accepts JSON/SARIF payloads from external webhooks and invokes normalizer.
- `POST /api/v1/integrations/test-webhook`: Dispatches a test payload to a user-provided webhook URL or mock sink.
- `GET /api/v1/integrations/status`: Reports status of configured integration sinks (Slack webhook, Jira export format, Inbound webhook state).
- `POST /api/v1/cases/{case_id}/export-ticket`: Returns a structured payload formatted for Jira or GitHub Issues.

### 3. Docker Sandbox (`src/app/api/docker_validation.py`)
- `GET /api/v1/sandbox/docker/status`: Reports Docker engine availability, container image cache, and sandbox policy status.
- `POST /api/v1/sandbox/docker/execute/{canonical_issue_id}`: Attempts ephemeral containerized validation run under strict isolation constraints.

---

## Acceptance Criteria

1. **AI Auto-Remediation**:
   - Successfully generates valid git diffs for SQLi, XSS, and SSRF canonical issues.
   - Secret redaction runs prior to sending prompt to LLM engine.
   - Fallback generator works deterministically if LLM API keys are absent.

2. **Integrations Hub**:
   - Inbound webhook endpoint ingests flat JSON or SARIF scanner arrays without errors.
   - Outbound test webhook dispatches formatted alerts and handles connection errors cleanly without crashing.
   - Case ticket exporter produces valid Jira/GitHub Markdown payloads containing canonical issue title, risk score, evidence summaries, and remediation recommendations.

3. **Docker Sandbox**:
   - Correctly detects whether Docker engine is available on the operating system.
   - Safely executes containerized probes when Docker is present, or returns clear HTTP 200/422 typed fallback status when Docker is absent or disabled.
   - Enforces execution timeouts and memory boundaries; raw output is sanitized and saved as immutable evidence with SHA-256 digests.
