# VulnTriager — Master Task Log & Progress Tracker

> Last Updated: 2026-09-11 22:28 IST | Project: KH044 Innov8ors | Status: IN PROGRESS — Phase 1
> This log is the source of truth for task state across all agents and computer systems.
> Every agent must read this file before starting work and update it when completing tasks.

---

## How to Use This Log (Agent Instructions)

1. **Before starting any task**: Read this file. Find your assigned task. Change its status from `[ ]` to `[/]`.
2. **After completing any task**: Change `[/]` to `[x]`. Add a short completion note (what was done, what file was changed, any known issues or blockers for the next task).
3. **If blocked**: Change status to `[!]` and write a blocker note. Do NOT skip to the next task — report first.
4. **Never mark a task `[x]` without actually running/testing it.**
5. **Commit after every completed task** with the format: `[task-id] feat: <what you built>`.

---

## Status Key
- `[ ]` — Not started
- `[/]` — In progress
- `[x]` — Completed & verified
- `[!]` — Blocked (see note)
- `[-]` — Skipped / deferred

---

## Decision Log

| Timestamp | Decision | Rationale |
|---|---|---|
| 2026-09-11 22:06 | Use `pydantic-settings` instead of raw `os.getenv()` | Automatic type coercion, .env file reading, validation built-in |
| 2026-09-11 22:06 | WAL mode + FK constraints enabled on SQLite | Better concurrent read performance; FK enforcement prevents orphaned data |
| 2026-09-11 22:06 | `threat_intelligence` uses `cve_id` as PK, not UUID | CVE IDs are the natural key; no need for surrogate UUID on this table |
| 2026-09-11 22:06 | Risk weight validation at Settings import time | Fail fast — bad config found at startup, not mid-request |
| 2026-09-11 22:06 | Removed redundant `load_dotenv()` from config.py | `pydantic-settings` handles .env natively via `model_config`; double-loading was redundant |
| 2026-09-11 22:06 | Added `python-dotenv==1.0.1` to requirements | `pydantic-settings` requires it as a dependency for .env file support |
| 2026-09-11 22:06 | All 13 DB tables created in one `init_db()` call | Simpler than migrations for prototype; `CREATE TABLE IF NOT EXISTS` is idempotent |
| 2026-09-11 22:20 | Install split: core deps first, ML deps (sentence-transformers, sklearn) separate | Windows App Control policy blocked full install; separate installs isolate the failure |
| 2026-09-11 22:27 | Binary wheel install `pydantic-2.13.5` & `pydantic-core-2.46.5` | Pydantic 2.9.2 failed metadata build on Python 3.14 on Windows; pre-built wheel `pydantic-2.13.5` installed cleanly |
| 2026-09-11 22:52 | Primary CWE Fingerprint resolution via `CWE_PARENT_MAP` | Child CWEs (CWE-564, CWE-80) resolve to root (CWE-89, CWE-79) before SHA-256 fingerprinting |
| 2026-09-11 22:52 | Non-destructive JSON ingestion parsing | Parser handles SARIF 2.1.0 (with runs/results), flat JSON arrays, single JSON objects, and Manual Entry DTOs |
| 2026-09-11 22:56 | ZAP Riskcode String Priority in Severity Mapping | Single-digit string riskcodes "0","1","2","3" checked before float CVSS parsing so ZAP code 3 maps to High |

---

## PHASE 0 — Project Setup & Documentation ✅

| ID | Task | Status | Notes |
|---|---|---|---|
| P0-06 | Create folder structure (`src/app/schemas/`, `parsers/`, `services/`, `repositories/`, `api/`, `static/`, `workers/`, `tests/`, `data/`) | `[x]` | All dirs created. Committed in `[P0-06]` commit (40 files). |
| P0-01 | Create `requirements.txt` with pinned dependencies | `[x]` | `src/app/requirements.txt` — 12 packages pinned. |
| P0-02 | Create `.env.example` with all config keys | `[x]` | `.env.example` — all 19 keys documented with inline comments. |
| P0-04 | Create `config.py` reading from `.env` | `[x]` | `src/app/config.py` — Pydantic Settings with risk weight sum validation. |
| P0-03 | Create `database.py` with all 13 table definitions | `[x]` | `src/app/database.py` — 13 tables + 12 indexes. WAL mode + FK constraints enabled. |
| P0-05 | Create `main.py` FastAPI entrypoint | `[x]` | `src/app/main.py` — lifespan startup, all 6 routers registered, `/health` endpoint. |
| P0-07 | Write updated `README.md` | `[x]` | `README.md` — full setup guide, project structure, tech stack table. |
| — | Create all stub files | `[x]` | All stubs created with `not_implemented` responses and module references. |

---

## PHASE 1 — Canonical Schema & Parsers ✅

| ID | Task | Status | Notes |
|---|---|---|---|
| M1-01 | Define `schemas/canonical.py` — NormalizedFinding, all sub-models | `[x]` | Implemented all sub-models + Ingestion DTOs (`ManualFindingCreate`, `DirectIngestPayload`, `BatchSummary`) |
| M1-02 | Define normalization utils: CVE, CWE, Severity, CVSS | `[x]` | `normalize_cve()`, `normalize_cwe()`, `normalize_severity()`, `derive_cvss_from_severity()`, `infer_parameter_class()` in `parsers/base.py` |
| M1-03 | Implement `compute_fingerprint()` function | `[x]` | `SHA256(cwe_primary + canonical_path + parameter_class)` with CWE root hierarchy resolution |
| M1-04 | Implement `parsers/base.py` — BaseScannerParser + registry | `[x]` | `BaseScannerParser` ABC, `PARSER_REGISTRY`, `BURP_RULE_TO_CWE`, `NESSUS_PLUGIN_TO_CWE`, `CWE_PARENT_MAP` |
| M1-05 | Implement `parsers/nessus.py` | `[x]` | `NessusParser` registered as `"nessus"`, with plugin_name CWE inference |
| M1-06 | Implement `parsers/burp.py` | `[x]` | `BurpParser` registered as `"burp"`, handling flat JSON exports |
| M1-07 | Implement `parsers/snyk.py` | `[x]` | `SnykParser` registered as `"snyk"`, handling SCA library vulnerabilities |
| M1-08 | Implement `parsers/trivy.py` | `[x]` | `TrivyParser` registered as `"trivy"`, handling container & library findings |
| M1-09 | Implement `parsers/sarif.py` — SARIF 2.1.0 + ZAP JSON | `[x]` | `GenericSARIFParser` registered as `"sarif"` and `ZAPParser` registered as `"zap"` |
| M1-10 | Implement `services/normalizer.py` — orchestrate parsers + validate | `[x]` | `NormalizerService` parsing, validation, quality scoring, batch handling, and repo persistence |
| M1-11 | Implement `api/ingestion.py` — POST /findings/upload, POST /findings | `[x]` | File upload (SARIF/JSON) + Direct JSON POST endpoints returning `BatchSummary` |
| M1-12 | **Manual Entry API** — POST /findings/manual with web form support | `[x]` | `POST /api/v1/findings/manual` endpoint normalizing manual web form entries |
| M1-13 | Write unit tests for all parsers | `[x]` | `tests/test_parsers.py` — 9 unit tests passing |
| M1-14 | Write unit tests for normalization utilities | `[x]` | `tests/test_normalizer.py` — 3 unit tests passing (12/12 overall test suite) |

---

## PHASE 2 — Synthetic Data (50 SQLi + 40 XSS + 20 SSRF) ✅

| ID | Task | Status | Notes |
|---|---|---|---|
| D1-01 | Generate `data/burp_sqli.sarif` — 25 SQLi findings in SARIF format | `[x]` | Generated 25 SARIF SQLi findings |
| D1-02 | Generate `data/nessus_sqli.json` — 25 SQLi findings in Nessus JSON | `[x]` | Generated 25 Nessus SQLi findings (5 cross-scanner dups) |
| D1-03 | Generate `data/burp_xss.sarif` — 20 XSS findings in SARIF format | `[x]` | Generated 20 SARIF XSS findings |
| D1-04 | Generate `data/zap_xss.json` — 20 XSS findings in OWASP ZAP JSON | `[x]` | Generated 20 ZAP XSS findings (8 cross-scanner dups) |
| D1-05 | Generate `data/burp_ssrf.json` — 10 SSRF findings | `[x]` | Generated 10 Burp SSRF findings |
| D1-06 | Generate `data/nessus_ssrf.sarif` — 10 SSRF findings in SARIF | `[x]` | Generated 10 Nessus SARIF SSRF findings (3 cross-scanner dups) |
| D1-07 | Generate `data/cisa_kev_mock.json` — 10 KEV entries | `[x]` | Generated KEV catalog mock with active exploitation flags |
| D1-08 | Generate `data/epss_mock.json` — EPSS scores for all CVEs used | `[x]` | Generated EPSS scores and percentiles mock data |

---

## PHASE 3 — Multi-View Extraction & Embeddings

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M2-01 | Define `schemas/views.py` — FindingViews, SingleView, ViewStatus | `[ ]` | — | See Module 3 spec |
| M2-02 | Implement `services/extractor.py` — Description view | `[ ]` | — | Structured fields → clean text |
| M2-03 | Implement `services/extractor.py` — Location view | `[ ]` | — | Canonical URL/path/param extraction |
| M2-04 | Implement `services/extractor.py` — Reproduction view | `[ ]` | — | From evidence.request; MISSING if absent |
| M2-05 | Implement `services/extractor.py` — Impact view | `[ ]` | — | CWE_IMPACT_MAP + keyword inference |
| M2-06 | Implement secret redaction before embedding text | `[ ]` | — | Regex patterns for auth headers, tokens |
| M2-07 | Add `api/findings.py` — GET views endpoint | `[ ]` | — | — |
| M2-08 | Implement `services/embedding.py` — SentenceTransformer wrapper | `[ ]` | — | all-MiniLM-L6-v2 model |
| M2-09 | Implement weighted cosine similarity scorer | `[ ]` | — | Used by deduplicator |
| M2-10 | Write tests for 4-view extraction (SQLi, XSS, SSRF cases) | `[ ]` | — | — |

---

## PHASE 4 — Deduplication Engine

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M3-01 | Define `schemas/dedup.py` — Cluster, CanonicalIssue | `[ ]` | — | — |
| M3-02 | Implement Stage A: deterministic fingerprint dedup | `[ ]` | — | CWE hierarchy + canonical path |
| M3-03 | Build `CWE_PARENT_MAP` dict for hierarchy resolution | `[ ]` | — | Static dict; CWE-564 → CWE-89, etc. |
| M3-04 | Implement Stage B: HDBSCAN semantic clustering | `[ ]` | — | scikit-learn HDBSCAN |
| M3-05 | Implement hard-block merge rules (no cross-param, no cross-package) | `[ ]` | — | Depends on M3-04 |
| M3-06 | Implement canonical issue creation from cluster | `[ ]` | — | Preserve all source findings |
| M3-07 | Implement `api/clusters.py` — GET, merge, split endpoints | `[ ]` | — | — |
| M3-08 | Write dedup tests: cross-scanner, same-endpoint-diff-param | `[ ]` | — | — |

---

## PHASE 5 — Threat Intel & Prioritization

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M4-01 | Implement `services/threat_intel.py` — KEV lookup (mock + live) | `[ ]` | — | Load from data/cisa_kev_mock.json |
| M4-02 | Implement EPSS lookup (mock + live toggle) | `[ ]` | — | Cache in SQLite threat_intel table |
| M4-03 | Define `schemas/risk.py` — PriorityResult | `[ ]` | — | — |
| M4-04 | Implement `services/risk_engine.py` — composite risk score | `[ ]` | — | Configurable weights, 0–100 score |
| M4-05 | Implement remediation tier assignment rules | `[ ]` | — | Immediate / Accelerated / Standard |
| M4-06 | Implement human-readable explanation generator | `[ ]` | — | List of factor contribution sentences |
| M4-07 | Add prioritization API endpoints | `[ ]` | — | — |
| M4-08 | Write risk engine tests (KEV → Immediate, no-CVE → Standard) | `[ ]` | — | — |

---

## PHASE 6 — Sandbox Validation & Evidence

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M5-01 | Define `schemas/validation.py` — ValidationResult, Artifact | `[ ]` | — | — |
| M5-02 | Implement Lab Simulator mode for SQLi, XSS, SSRF scenarios | `[ ]` | — | Dict of CWE→verdict+evidence |
| M5-03 | Implement real Docker sandbox mode (feature-flagged OFF) | `[ ]` | — | SANDBOX_ENABLED=false default |
| M5-04 | Implement evidence capture + SHA-256 hashing | `[ ]` | — | All artifacts immutable |
| M5-05 | Implement secret redaction in evidence before display | `[ ]` | — | — |
| M5-06 | Add validation API endpoints | `[ ]` | — | — |
| M5-07 | Write sandbox tests: timeout=inconclusive, allowlist reject | `[ ]` | — | — |

---

## PHASE 7 — Case Generation & Human Review

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M6-01 | Define `schemas/case.py` — Case, ReviewAction, AuditEvent | `[ ]` | — | — |
| M6-02 | Implement `services/case_service.py` — case assembly | `[ ]` | — | Aggregates all pipeline outputs |
| M6-03 | Implement case state machine (pending → approved/rejected) | `[ ]` | — | Reject MUST have reason |
| M6-04 | Implement append-only audit event log | `[ ]` | — | Immutable, timestamped |
| M6-05 | Implement `api/cases.py` — all case endpoints + review actions | `[ ]` | — | — |
| M6-06 | Write case generation tests | `[ ]` | — | — |

---

## PHASE 8 — Analyst Dashboard (Frontend)

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| F1-01 | Build Panel 1: Triage Overview metrics bar | `[ ]` | — | Calls /dashboard/metrics |
| F1-02 | Build Panel 2: File upload + manual entry form | `[ ]` | — | Scanner type dropdown + JSON textarea |
| F1-03 | Build Panel 3: Case queue table (sortable, filterable) | `[ ]` | — | Tier badge colors |
| F1-04 | Build Panel 4: Case detail with 4-view accordion | `[ ]` | — | Risk score gauge + explanation |
| F1-05 | Build Panel 5: Cluster inspector side-by-side diff | `[ ]` | — | Merge/Split/Keep actions |
| F1-06 | Build approve/reject modals with mandatory reason | `[ ]` | — | No approve without comment |
| F1-07 | Add audit timeline panel to case detail | `[ ]` | — | — |

---

## PHASE 9 — Integration & Demo Prep

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| I1-01 | Wire full pipeline "Run Pipeline" button | `[ ]` | — | Calls all stages in sequence |
| I1-02 | End-to-end integration test across all 110 synthetic findings | `[ ]` | — | — |
| I1-03 | Demo scenario scripts (SQLi cluster, SSRF, Log4j) | `[ ]` | — | Run before demo |
| I1-04 | Final README + architecture diagram | `[ ]` | — | — |

---

## PHASE 10 — Future Scope (Post-Hackathon)

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| FS-01 | Slack integration: notify channel on new Immediate-tier case | `[ ]` | — | Webhook-based |
| FS-02 | Jira integration: auto-create ticket on case approval | `[ ]` | — | Jira REST API |
| FS-03 | Autonomous ingestion API: scheduled scanner API polling | `[ ]` | — | Replaces manual upload |
| FS-04 | Real-time ingestion webhook: scanners push findings directly | `[ ]` | — | — |

---

## Completion Summary

| Phase | Tasks | Done | Remaining |
|---|---|---|---|
| Phase 0 — Setup | 7 | 7 | 0 |
| Phase 1 — Parsers | 14 | 0 | 14 |
| Phase 2 — Data | 8 | 0 | 8 |
| Phase 3 — Views & Embeddings | 10 | 0 | 10 |
| Phase 4 — Deduplication | 8 | 0 | 8 |
| Phase 5 — Threat Intel | 8 | 0 | 8 |
| Phase 6 — Sandbox | 7 | 0 | 7 |
| Phase 7 — Cases | 6 | 0 | 6 |
| Phase 8 — Frontend | 7 | 0 | 7 |
| Phase 9 — Demo | 4 | 0 | 4 |
| **TOTAL** | **79** | **7** | **72** |
