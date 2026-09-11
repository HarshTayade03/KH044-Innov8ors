# VulnTriager — Cross-Agent & Cross-System Development Instructions

> **THIS FILE IS THE AUTHORITATIVE AGENT CONTEXT DOCUMENT.**
> Every agent on every computer system must read this file completely before beginning any work.
> Do not trust memory from a previous session. Always re-read this file.

---

## 1. Project Identity

- **Project Name**: VulnTriager (internal name only — do NOT use this name in public-facing materials or UI copy)
- **Public Name**: AI-Assisted Vulnerability Triage Platform (use this in UI, READMEs, and presentations)
- **Team**: KH044 Innov8ors
- **Repository**: `innov8ors/` (currently at `c:/Users/harsh/Downloads/innov8ors/` on the primary dev machine)
- **Branch strategy**: Always create a feature branch off `main`. Format: `feature/<module-id>-<short-description>`. Never commit directly to `main`.
- **Language & Runtime**: Python 3.14 (backend), vanilla HTML/CSS/JS (frontend — no build step)
- **Package manager**: `pip` with `requirements.txt` (pinned versions)

---

## 2. Project Purpose (30-Second Summary for Any Agent)

Security teams receive thousands of disorganized vulnerability alerts from multiple scanners (Nessus, Burp Suite, OWASP ZAP, SARIF-format tools). They manually deduplicate, verify, and prioritize — an error-prone, time-consuming process.

This system automates that pipeline:
1. **Ingest** findings from multiple scanners (JSON, SARIF, or manual entry form)
2. **Normalize** all findings to a single canonical schema
3. **Deduplicate** using deterministic fingerprinting + AI semantic clustering
4. **Validate** exploitability in a safe, isolated sandbox simulation
5. **Prioritize** with transparent risk scoring (CISA KEV + EPSS + CVSS + asset context)
6. **Generate** analyst-ready cases
7. **Review** — human analyst approves/rejects every case (final authority stays human)

---

## 3. Synthetic Data Focus (For This Prototype)

The prototype uses **110 synthetic vulnerability findings** split as:
- **50 SQL Injection (SQLi)** findings — CWE-89 and CWE-564 (child of 89) — delivered in both Nessus JSON (25) and Burp SARIF (25). Several cross-scanner duplicates intentional.
- **40 Cross-Site Scripting (XSS)** findings — CWE-79 — delivered in both Burp SARIF (20) and OWASP ZAP JSON (20). Mix of reflected and stored XSS.
- **20 Server-Side Request Forgery (SSRF)** findings — CWE-918 — split across Burp JSON (10) and Nessus SARIF (10).

Edge cases intentionally embedded in the data:
- Same vulnerability on same endpoint from 2 different scanners (cross-scanner dup)
- Same vulnerability type on same host but different URL parameters (must NOT be deduped)
- Findings with no CVE (business logic / CWE-only)
- Findings with qualitative severity only (no CVSS score)
- Conflicting severities for the same finding across scanners (one says HIGH, one says MEDIUM)
- A finding appearing in both Monday and Tuesday synthetic scan runs (cross-run dup)

---

## 4. Ingestion Methods (Prototype Scope)

The prototype supports **3 ingestion methods** — autonomous API is future scope:

| Method | Description | API Endpoint |
|---|---|---|
| **File Upload** | Upload a JSON or SARIF file + declare the source scanner | `POST /api/v1/findings/upload` |
| **Direct JSON POST** | Send raw JSON array of findings programmatically | `POST /api/v1/findings` |
| **Manual Entry Form** | Web form in the dashboard for entering 1 finding by hand | `POST /api/v1/findings/manual` |

Future (post-prototype):
- Autonomous API polling: scheduled jobs calling live scanner APIs (Nessus API, Burp REST API)
- Webhook push: scanners post directly to `/api/v1/ingest/webhook`
- Slack notification on Immediate-tier cases
- Jira ticket auto-creation on case approval

---

## 5. File and Module Map (Source of Truth)

Every agent must use these exact file paths. Never create files outside this structure without updating this document.

```
innov8ors/
├── src/app/
│   ├── main.py                        # FastAPI app entrypoint. ALL routers registered here.
│   ├── config.py                      # Single config object. Read from .env via os.getenv.
│   ├── database.py                    # SQLite init. Call init_db() from main.py startup.
│   ├── schemas/
│   │   ├── canonical.py               # NormalizedFinding (the master schema)
│   │   ├── views.py                   # FindingViews, SingleView, ViewStatus
│   │   ├── dedup.py                   # Cluster, CanonicalIssue, DupStatus
│   │   ├── validation.py              # ValidationResult, Artifact, SandboxMode
│   │   ├── risk.py                    # PriorityResult, RemediationTier
│   │   └── case.py                    # Case, ReviewAction, AuditEvent, CaseStatus
│   ├── parsers/
│   │   ├── base.py                    # BaseScannerParser ABC + PARSER_REGISTRY dict
│   │   ├── nessus.py                  # NessusParser
│   │   ├── burp.py                    # BurpParser (also handles Burp SARIF via flag)
│   │   ├── snyk.py                    # SnykParser
│   │   ├── trivy.py                   # TrivyParser
│   │   └── sarif.py                   # GenericSARIFParser (handles SARIF 2.1.0 + Nuclei)
│   ├── services/
│   │   ├── normalizer.py              # Orchestrates parser → validate → persist
│   │   ├── extractor.py               # 4-view extraction + secret redaction
│   │   ├── embedding.py               # SentenceTransformer wrapper
│   │   ├── deduplicator.py            # Fingerprint + HDBSCAN clustering
│   │   ├── sandbox.py                 # PoC execution (lab simulator or Docker)
│   │   ├── threat_intel.py            # CISA KEV + EPSS enrichment
│   │   ├── risk_engine.py             # Composite risk score + tier assignment
│   │   └── case_service.py            # Case generation + review state machine
│   ├── repositories/
│   │   └── findings_repo.py           # ALL database read/write goes through here
│   ├── api/
│   │   ├── ingestion.py               # /findings/upload, /findings, /findings/manual
│   │   ├── findings.py                # /findings GET endpoints
│   │   ├── clusters.py                # /clusters + merge/split
│   │   ├── validation.py              # /validate + evidence
│   │   ├── cases.py                   # /cases + approve/reject/override
│   │   └── dashboard.py               # /dashboard/metrics
│   └── static/
│       └── index.html                 # Single-file analyst dashboard (NO build step)
├── data/
│   ├── burp_sqli.sarif                # 25 SQLi findings — Burp SARIF format
│   ├── nessus_sqli.json               # 25 SQLi findings — Nessus JSON format
│   ├── burp_xss.sarif                 # 20 XSS findings — Burp SARIF format
│   ├── zap_xss.json                   # 20 XSS findings — OWASP ZAP JSON format
│   ├── burp_ssrf.json                 # 10 SSRF findings — Burp JSON format
│   ├── nessus_ssrf.sarif              # 10 SSRF findings — Nessus SARIF format
│   ├── cisa_kev_mock.json             # 10 KEV entries (mock)
│   └── epss_mock.json                 # EPSS scores for all CVEs used in dataset
├── tests/
│   ├── test_parsers.py
│   ├── test_normalizer.py
│   ├── test_extractor.py
│   ├── test_deduplicator.py
│   ├── test_risk_engine.py
│   └── test_api.py
├── docs/
│   ├── project_f1.md                  # Original hackathon problem statement (READ-ONLY)
│   ├── vulntriager_product_reference.md  # Full product spec (READ-ONLY reference)
│   ├── normal.txt                     # Normalization schema spec (READ-ONLY reference)
│   ├── agent-instructions.md          # THIS FILE (update if project scope changes)
│   ├── MODULE_SPECS/                  # Detailed specs per module — always read before implementing
│   │   ├── M0_bootstrap.md
│   │   ├── M1_parsers_normalizer.md
│   │   ├── M2_views_embeddings.md
│   │   ├── M3_deduplication.md
│   │   ├── M4_threat_intel_risk.md
│   │   ├── M5_sandbox_evidence.md
│   │   ├── M6_cases_review.md
│   │   └── M7_dashboard.md
├── requirements.txt
├── .env.example
└── README.md
```

---

## 6. Global Rules (All Agents, All Modes, Always)

1. **Read before writing.** Before editing any file, read it first. Never assume its current contents.
2. **Read the module spec first.** Before implementing any module, read `docs/MODULE_SPECS/M<N>_<name>.md` completely.
3. **Update the task log.** Read and update `task.md` (in the artifacts dir or root) before and after every task.
4. **No secrets in code.** Never hardcode API keys, passwords, or tokens. Use `.env` only.
5. **Never commit to main.** Always use a branch: `feature/<task-id>-<description>`.
6. **Time-box.** Flag any task estimated >30 min before starting. Propose a shortcut.
7. **Leave it runnable.** `python -m uvicorn src.app.main:app --reload` must always work when you finish.
8. **Small commits.** After each task in task.md, commit: `[<task-id>] feat: <what>`
9. **No hallucinating APIs.** Verify function names and API shapes from the actual schema files before calling them.
10. **Never invent findings data.** When generating synthetic data, follow the formats exactly as specified in `docs/MODULE_SPECS/M1_parsers_normalizer.md`.

---

## 7. Development Modes (Tag Your Work)

When starting a task, prefix your output/commit with the mode:

| Tag | When to Use |
|---|---|
| `[MODE: DEVELOPMENT]` | Building a new feature from the spec |
| `[MODE: DEBUGGING]` | Fixing a broken thing |
| `[MODE: VALIDATION]` | Running tests to confirm behavior |
| `[MODE: INTEGRATION]` | Connecting two modules together |
| `[MODE: DEMO-PREP]` | Hardening for final demo |

---

## 8. Architecture Principles (Do Not Violate)

- **Every module reads from `repositories/findings_repo.py`** — no module talks to SQLite directly except the repo.
- **Every module writes through the repo** — all persistence is centralized.
- **Schemas are contracts** — never change a Pydantic schema field name or type without updating ALL modules that use it and noting it as breaking.
- **Original evidence is immutable** — once ingested, raw evidence is never overwritten. Only add.
- **Inference ≠ confirmation** — impact and reproduction views are always labeled `inferred` until sandbox confirms them. Never claim exploitability from scanner data alone.
- **Human approval is final** — no automated system approves or closes a case. Only human analyst actions change case status to `approved` or `rejected`.

---

## 9. Tech Stack Decisions (Locked — Do Not Change Without Team Discussion)

| Layer | Choice | Reason |
|---|---|---|
| Backend framework | FastAPI + Pydantic v2 | Type-safe, auto-generates OpenAPI docs |
| Database | SQLite (single file) | Zero-setup for prototype |
| Embeddings | `sentence-transformers` — `all-MiniLM-L6-v2` | Runs offline, fast, 384-dim |
| Clustering | `scikit-learn` HDBSCAN | No fixed cluster count needed |
| Frontend | Single `index.html` — Tailwind CDN + Alpine.js CDN | No build step, portable |
| Testing | `pytest` + `httpx` (FastAPI test client) | Standard |
| Data formats | SARIF 2.1.0 + JSON | As specified by problem statement |

---

## 10. Future Scope (Do NOT Implement in Prototype — Stub Only)

- **Slack Webhook**: On new `Immediate` tier case → POST to Slack webhook URL (env var `SLACK_WEBHOOK_URL`). Stub in `services/notifier.py` with a `TODO` comment.
- **Jira Integration**: On `case.status = approved` → POST to Jira REST API creating a bug ticket. Stub in `services/jira_client.py`.
- **Autonomous Scanner API Polling**: Scheduled job (cron/celery) calling live Nessus/Burp APIs to pull new findings automatically. Stub in `workers/scanner_poller.py`.
- **Direct Webhook Ingest**: Scanners push findings to `POST /api/v1/ingest/webhook`. Stub endpoint only.

---

## 11. Quick Setup (Any New Machine)

```bash
# 1. Clone or copy the repo
cd innov8ors

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy env file and fill in values
copy .env.example .env

# 5. Run the server
python -m uvicorn src.app.main:app --reload --port 8000

# 6. Open dashboard
# Navigate to: http://localhost:8000/

# 7. Run tests
pytest tests/ -v
```

---

## 12. Key Decisions Log

| Date | Decision | Reason |
|---|---|---|
| 2026-09-11 | Use SQLite over PostgreSQL | Zero-setup for hackathon prototype |
| 2026-09-11 | Single index.html frontend | No build step, works on any machine |
| 2026-09-11 | SANDBOX_ENABLED=false by default | Lab simulator for offline/demo reliability |
| 2026-09-11 | Manual entry as ingestion method | Prototype priority; no live scanner APIs |
| 2026-09-11 | 50 SQLi / 40 XSS / 20 SSRF synthetic data | Covers 3 major web vuln classes; realistic distribution |
| 2026-09-11 | SARIF 2.1.0 + JSON as primary input formats | Matches problem statement requirement |
| 2026-09-11 | Slack & Jira as future scope stubs only | Time constraints; stub API is sufficient for demo |
