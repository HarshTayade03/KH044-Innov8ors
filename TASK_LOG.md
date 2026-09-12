# AI-Assisted Triage — Master Task Log & Progress Tracker

> Last Updated: 2026-09-12 IST | P6 LAB VALIDATION COMPLETE | Next 12-hour critical path: P7 reviewable cases and integrated analyst flow
> This log is the source of truth for task state across all agents and computer systems.
> Every agent must read this file before starting work and update it when completing tasks.

## Product information architecture and detection controls (2026-09-12)

- Split the public product landing page (`/`) from the operational analyst console (`/console`).
- Added official product documentation at `/documentation`; `/docs` remains the generated OpenAPI reference.
- Added independent console actions for view/embedding extraction, duplicate detection, and risk scoring,
  while retaining the complete pipeline action.
- Documented evidence provenance, human review, simulated validation boundaries, and deferred integrations.
- Verification: targeted route tests `4 passed`; `node --check src\\app\\static\\dashboard.js`;
  `git diff --check`; live HTTP smoke checks for `/`, `/console`, `/documentation`, and `/health`.

## Product surface and global audit log (2026-09-12)

- Expanded the landing page into a longer product narrative covering intake, views, deduplication,
  risk, controlled validation, cases, review, provenance, and safe boundaries.
- Added `GET /api/v1/audit-events` with entity/actor filters and pagination over immutable audit events.
- Added an Audit log tab to the analyst console with timestamp, action, entity, actor, and details.
- Verification: targeted audit/routes `5 passed`; full suite `67 passed, 2 skipped`; frontend syntax and live route checks passed.

## Threat feeds and analyst resolution (2026-09-12)

- Added explicit CISA KEV, NIST NVD, and FIRST EPSS feed status contracts and console visibility.
- Added opt-in live per-CVE NVD/EPSS refresh; local mock feeds remain the safe deterministic default.
- Added analyst resolve action. Resolving a case records actor/reason/audit history, marks the case
  resolved, retires the canonical issue from active queues, and preserves underlying evidence.
- Verification: feed and resolution regression coverage added; full suite `69 passed, 2 skipped`;
  `node --check`, `git diff --check`, and live feed/console/documentation route checks passed.

## Responsive analyst console layout (2026-09-12)

- Reworked console navigation, pipeline actions, evidence controls, metrics, feed cards, and
  table containers to wrap or scroll within their own regions at tablet/mobile widths.
- Fixed the pipeline action grid so long labels cannot push buttons outside the viewport.
- Verification: console route tests `4 passed`; JavaScript syntax and whitespace checks passed;
  browser geometry inspection found no non-decorative viewport overflow.

## Feature benchmark hardening (2026-09-12)

- Replaced the dashboard metrics HTTP 501 stub with read-only aggregate queries and an
  explicit provenance contract for offline simulation/mock threat intelligence.
- Bounded LLM contextual synthesis with a Pydantic response contract, evidence basis, and
  uncertainty fields; malformed provider output is rejected and falls back to the existing
  deterministic rules path.
- Batch validation now surfaces per-issue failures instead of silently discarding them.
- Verification: full suite `63 passed, 2 skipped`; `node --check src\\app\\static\\dashboard.js`,
  `git diff --check`, `pip check`, and live HTTP smoke checks for `/health` and
  `/api/v1/dashboard/metrics` all passed.

## Analyst operations pass (2026-09-12)

- Added a dedicated Cases view to the evidence explorer with pending-review, evidence-requested,
  and resolved states visible in one searchable queue.
- Added console actions to create a case from an active canonical issue, approve a case, request
  more evidence, and resolve the linked issue while preserving the existing audit trail.
- Added an export action for the current worklist view as a JSON artifact, keeping exports honest
  about their source data and avoiding unsupported external integrations.
- Verification: `node --check src\\app\\static\\dashboard.js` and `git diff --check` passed.

## Workflow partial-validation fix (2026-09-12)

- Batch sandbox validation now returns successful results and per-issue rejection details
  together. A blocked/non-allowlisted issue no longer aborts the entire workflow or hides
  validations that completed safely.
- The analyst console reports these as warnings and keeps the sandbox step complete, while
  retaining the failure details in the API response and validation state.
- Added a regression test for mixed allowlisted and rejected issues.

## Benchmark catalog and government-feed provenance (2026-09-12)

- Added `GET /api/v1/benchmarks`, a read-only catalog for the six authorized
  benchmark sources with purpose, expected artifacts, authorization requirements,
  and explicit isolated-lab safety policy.
- Added official NIST NVD, CISA KEV, and FIRST EPSS endpoint configuration while
  retaining local mock feeds and disabled live refresh as the deterministic default.
- Verification complete (65 passed, 2 skipped across test suite); live feed polling remains intentionally
  deferred until rate limits, response hashing, and refresh persistence are specified.

## Contextual Sandbox Validation & LLM Prioritization — `feature/sandbox-llm-prioritization` (2026-09-12)

- Implemented pipeline reordering: Deduplication → Sandbox Validation → Contextual Prioritization.
- Multi-Artifact Evidence: Each sandbox run now produces 4 immutable, redacted artifacts (`http_request`, `http_response`, `execution_log`, `validation_summary`) with verified SHA-256 digests.
- Hierarchy & Allowlist Normalization: Integrated `resolve_cwe_root()` to map child CWE variants (e.g. `CWE-564` → `CWE-89`) and host allowlist checking.
- LLM Synthesis Engine (`llm_prioritizer.py`): Supports Groq (free fast inference for demos), Gemini, OpenAI, and Mock providers with pre-call secret redaction and structured JSON output.
- Frontend Console Enhancements: Reordered 5-step workflow track in `index.html` and `dashboard.js`, added Validations table tab and header metric, added 4-artifact inspector modal and LLM synthesis cards in issue inspection.
- Verification: `62 passed, 2 skipped` (`venv\Scripts\python.exe -m pytest tests/ -v`); `node --check src\app\static\dashboard.js` passed.

## Integration Verification — `feature/hackathon-verification` (2026-09-12)

- Merged `feature/core-risk-flow`, `feature/debug-verification`, and
  `feature/frontend-feature-access` in that order from `origin/main`.
- Preserved unrelated working-tree files: `src/app/parsers/__init__.py`,
  `data/pipeline_testing_guide.md`, and `data/sample_upload.json`.
- Added an accessible legacy console label to the public-name frontend header so the
  existing startup contract remains compatible without changing the displayed product name.
- Verification: `58 passed, 2 skipped` (`venv\Scripts\python.exe -m pytest tests\ -q`);
  `pip check` passed; `node --check src\app\static\dashboard.js` passed; `git diff --check`
  passed. Uvicorn smoke checks returned HTTP 200 for `/`, `/health`, and `/openapi.json`;
  the server was stopped afterward.

## Frontend case inspection fix — `feature/fix-frontend-case-inspection` (2026-09-12)

- Reproduced the case queue contract mismatch: `GET /api/v1/cases?limit=500` returns a JSON
  array, while the console only read object-wrapped collections, so the queue always rendered
  empty. The refresh path now accepts both response shapes and reports partial-load failures.
- Case inspection now surfaces the assembled latest offline validation, redacted evidence
  references, stale status, and audit events; terminal cases no longer show review controls.
- Verification: `node --check src\app\static\dashboard.js`, `git diff --check`, and local
  Uvicorn checks for `/health` and `/api/v1/cases?limit=500` (HTTP 200, array response) passed.
  Existing unrelated working-tree files were preserved.

## Backend case query/review fix — `feature/fix-backend-case-queries` (2026-09-12)

- Reproduced two backend inspection defects: case detail returned audit events but omitted the
  persisted review history, and `priority_override` incorrectly changed a pending case to
  `more_evidence_requested`. Invalid case-list status strings were also accepted as empty
  results rather than rejected by FastAPI validation.
- Added review-history retrieval to case detail, constrained list status to `CaseStatus`, and
  kept priority overrides in the current reviewable state while still recording the review and
  audit event. Added regression coverage for override state and inspection history.
- Verification: focused case tests `3 passed`; full suite verification pending before commit.

---

## Backend case query/review fix — `feature/fix-backend-case-queries` (2026-09-12)

- Reproduced two backend inspection defects: case detail returned audit events but omitted the
  persisted review history, and `priority_override` incorrectly changed a pending case to
  `more_evidence_requested`. Invalid case-list status strings were also accepted as empty
  results rather than rejected by FastAPI validation.
- Added review-history retrieval to case detail, constrained list status to `CaseStatus`, and
  kept priority overrides in the current reviewable state while still recording the review and
  audit event. Added regression coverage for override state and inspection history.
- Verification: focused case tests `3 passed`; full suite `59 passed, 2 skipped`.

---

## Backend case query/review fix — `feature/fix-backend-case-queries` (2026-09-12)

- Reproduced two backend inspection defects: case detail returned audit events but omitted the
  persisted review history, and `priority_override` incorrectly changed a pending case to
  `more_evidence_requested`. Invalid case-list status strings were also accepted as empty
  results rather than rejected by FastAPI validation.
- Added review-history retrieval to case detail, constrained list status to `CaseStatus`, and
  kept priority overrides in the current reviewable state while still recording the review and
  audit event. Added regression coverage for override state and inspection history.
- Verification: focused case tests `3 passed`; full suite `59 passed, 2 skipped`.

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
| 2026-09-11 22:06 | All 14 DB tables created in one `init_db()` call | Simpler than migrations for prototype; `CREATE TABLE IF NOT EXISTS` is idempotent |
| 2026-09-11 22:20 | Install split: core deps first, ML deps (sentence-transformers, sklearn) separate | Windows App Control policy blocked full install; separate installs isolate the failure |
| 2026-09-11 22:27 | Binary wheel install `pydantic-2.13.5` & `pydantic-core-2.46.5` | Pydantic 2.9.2 failed metadata build on Python 3.14 on Windows; pre-built wheel `pydantic-2.13.5` installed cleanly |
| 2026-09-11 22:52 | Primary CWE Fingerprint resolution via `CWE_PARENT_MAP` | Child CWEs (CWE-564, CWE-80) resolve to root (CWE-89, CWE-79) before SHA-256 fingerprinting |
| 2026-09-11 22:52 | Non-destructive JSON ingestion parsing | Parser handles SARIF 2.1.0 (with runs/results), flat JSON arrays, single JSON objects, and Manual Entry DTOs |
| 2026-09-11 22:56 | ZAP Riskcode String Priority in Severity Mapping | Single-digit string riskcodes "0","1","2","3" checked before float CVSS parsing so ZAP code 3 maps to High |
| 2026-09-11 23:18 | Multi-view secret redaction regex filtering | Apply secret redaction to reproduction/location text BEFORE storing in `view_text` |
| 2026-09-11 23:24 | sklearn `HashingVectorizer` fallback for sentence embeddings | Guarantees vector embeddings even if `sentence-transformers` ML package is absent |
| 2026-09-11 23:24 | Two-Stage Deduplication (Fingerprint + HDBSCAN) | Stage A groups exact fingerprints, Stage B performs HDBSCAN semantic density clustering |
| 2026-09-11 23:38 | Composite Risk Scoring + KEV/EPSS Enrichment | 0–100 risk score combining weighted CVSS, EPSS, CISA KEV flag, asset criticality, network exposure |
| 2026-09-12 02:25 | 12-hour core-feature execution backlog | Contextualisation, prioritization, and sandbox evidence follow one traceable analyst flow; raw evidence stays preserved, derived artifacts are sanitized, mock/simulated results stay labeled, and humans alone approve or reject cases |

---

## PHASE 0 — Project Setup & Documentation ✅

| ID | Task | Status | Notes |
|---|---|---|---|
| P0-06 | Create folder structure (`src/app/schemas/`, `parsers/`, `services/`, `repositories/`, `api/`, `static/`, `workers/`, `tests/`, `data/`) | `[x]` | All dirs created. Committed in `[P0-06]` commit (40 files). |
| P0-01 | Create `requirements.txt` with pinned dependencies | `[x]` | `requirements.txt` — 12 packages pinned. |
| P0-02 | Create `.env.example` with all config keys | `[x]` | `.env.example` — all 19 keys documented with inline comments. |
| P0-04 | Create `config.py` reading from `.env` | `[x]` | `src/app/config.py` — Pydantic Settings with risk weight sum validation. |
| P0-03 | Create `database.py` with all 14 table definitions | `[x]` | `src/app/database.py` — 14 tables + 12 indexes. WAL mode + FK constraints enabled. |
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

## PHASE 3 — Multi-View Extraction & Embeddings ✅

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M2-01 | Define `schemas/views.py` — FindingViews, SingleView, ViewStatus | `[x]` | Agent | Implemented ViewStatus, SingleView, ViewQuality, FindingViews, FindingEmbeddings |
| M2-02 | Implement `services/extractor.py` — Description view | `[x]` | Agent | Implemented Description view extraction with boilerplate stripping |
| M2-03 | Implement `services/extractor.py` — Location view | `[x]` | Agent | Implemented Location view extraction with path canonicalization |
| M2-04 | Implement `services/extractor.py` — Reproduction view | `[x]` | Agent | Implemented Reproduction view extraction with HTTP request parsing |
| M2-05 | Implement `services/extractor.py` — Impact view | `[x]` | Agent | Implemented Impact view extraction with CWE_IMPACT_MAP and keyword inference |
| M2-06 | Implement secret redaction before embedding text | `[x]` | Agent | Implemented `redact_secrets()` regex filter |
| M2-07 | Add `api/findings.py` — GET/POST views & embeddings endpoints | `[x]` | Agent | Implemented batch/single view & embedding API routes |
| M2-08 | Implement `services/embedding.py` — SentenceTransformer wrapper | `[x]` | Agent | Implemented `EmbeddingService` with HashingVectorizer fallback |
| M2-09 | Implement weighted cosine similarity scorer | `[x]` | Agent | Implemented `cosine_similarity` and `weighted_similarity` |
| M2-10 | Write tests for 4-view extraction (SQLi, XSS, SSRF cases) | `[x]` | Agent | `tests/test_extractor.py` passing |

---

## PHASE 4 — Deduplication Engine ✅

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M3-01 | Define `schemas/dedup.py` — Cluster, CanonicalIssue | `[x]` | Agent | Defined Cluster, CanonicalIssue, ClusterMember, DedupRunSummary |
| M3-02 | Implement Stage A: deterministic fingerprint dedup | `[x]` | Agent | Fingerprint grouping in `DeduplicationEngine` |
| M3-03 | Build `CWE_PARENT_MAP` dict for hierarchy resolution | `[x]` | Agent | Implemented in `parsers/base.py` |
| M3-04 | Implement Stage B: HDBSCAN semantic clustering | `[x]` | Agent | Implemented HDBSCAN density clustering on distance matrix |
| M3-05 | Enforce hard-block merge rules in both stages and final clusters | `[x]` | R0 | Resolved 2026-09-12 with pairwise grouping, final checks and regression tests. |
| M3-06 | Implement canonical issue creation from cluster | `[x]` | Agent | Implemented `create_canonical_issues()` |
| M3-07 | Implement `api/clusters.py` — GET, merge, split endpoints | `[x]` | Agent | Implemented `/deduplication/run`, `/clusters`, `/canonical-issues`, merge/split |
| M3-08 | Write dedup tests: cross-scanner, same-endpoint-diff-param | `[x]` | Agent | `tests/test_dedup.py` passing |

---

## PHASE 5 — Threat Intel & Prioritization ✅

| ID | Task | Status | Owner | Notes |
|---|---|---|---|---|
| M4-01 | Implement `services/threat_intel.py` — KEV lookup (mock + live) | `[x]` | Agent | Implemented CISA KEV catalog lookup & DB caching |
| M4-02 | Implement EPSS lookup (mock + live toggle) | `[x]` | Agent | Implemented FIRST.org EPSS score/percentile lookup & DB caching |
| M4-03 | Define `schemas/risk.py` — PriorityResult | `[x]` | Agent | Defined PriorityResult, RemediationTier, ThreatEnrichment, RiskFactors |
| M4-04 | Implement `services/risk_engine.py` — composite risk score | `[x]` | Agent | 0–100 composite score with configurable weights |
| M4-05 | Implement remediation tier assignment rules | `[x]` | Agent | Rules: Immediate (KEV or >=80), Accelerated (>=50), Standard |
| M4-06 | Implement human-readable explanation generator | `[x]` | Agent | Sentence generator describing risk factor weights & score contribution |
| M4-07 | Add prioritization API endpoints | `[x]` | Agent | `/canonical-issues/{id}/prioritize`, `/priorities`, `/priorities/{id}` |
| M4-08 | Write risk engine tests (KEV → Immediate, no-CVE → Standard) | `[x]` | Agent | `tests/test_risk_engine.py` — 3 unit tests passing |

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
| M6-01 | Define `schemas/case.py` — Case, ReviewAction, AuditEvent | `[x]` | `schemas/case.py`, M6 spec | Contracts implemented; tested 2026-09-12 |
| M6-02 | Implement `services/case_service.py` — case assembly | `[x]` | `services/case_service.py`, `repositories/case_repo.py` | Active issue snapshot includes findings/views/priority/validation/evidence; baseline tests + case test pass |
| M6-03 | Implement case state machine (pending → approved/rejected) | `[x]` | `services/case_service.py` | Actor/reason required; terminal transitions conflict; evidence requests supported |
| M6-04 | Implement append-only audit event log | `[x]` | `repositories/case_repo.py` | Review and audit inserted in same transaction |
| M6-05 | Implement `api/cases.py` — all case endpoints + review actions | `[x]` | `api/cases.py` | Generate/list/detail and review routes wired |
| M6-06 | Write case generation tests | `[x]` | `tests/test_cases.py` | `venv\Scripts\python.exe -m pytest tests\test_baseline.py tests\test_cases.py -q`: 4 passed |

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

## Original Baseline Summary (audit-adjusted; remaining includes deferred tasks)

| Phase | Tasks | Done | Remaining |
|---|---|---|---|
| Phase 0 — Setup | 7 | 7 | 0 |
| Phase 1 — Parsers | 14 | 14 | 0 |
| Phase 2 — Data | 8 | 8 | 0 |
| Phase 3 — Views & Embeddings | 10 | 10 | 0 |
| Phase 4 - Deduplication | 8 | 8 | 0 |
| Phase 5 - Threat Intel | 8 | 6 | 2 |
| Phase 6 — Sandbox | 7 | 0 | 7 |
| Phase 7 — Cases | 6 | 0 | 6 |
| Phase 8 — Frontend | 7 | 0 | 7 |
| Phase 9 — Demo | 4 | 0 | 4 |
| **TOTAL** | **79** | **53** | **26** |

---

## 2026-09-12 Repository Audit and Replanned Work

Historical phase headings/pass claims above describe previous sessions, not fresh verification.
The adjusted 79-task baseline excludes the unnamed bootstrap stub row, P10, and new tasks below.
Remaining includes three deferred tasks (M4-01 live, M4-02 live, M5-03 Docker).

| ID | Task | Status | Evidence / result |
|---|---|---|---|
| DOC-01 | Establish discoverable agent instructions | `[x]` | Added root AGENTS.md; replaced stale machine paths, nonexistent specs and single-repo claims in development guide. |
| DOC-02 | Inventory modules and current done work | `[x]` | docs/CURRENT_STATE.md maps code, stubs, API surface and limitations; corrected 14-table count and hashing fallback description. |
| DOC-03 | Redesign implementation plan | `[x]` | docs/IMPLEMENTATION_PLAN.md defines R0 then P6-P9 with acceptance gates and a P6 contract; live integrations/Docker deferred. |
| DOC-04 | Align README, documentation index and task log | `[x]` | Local links, fixture counts and git diff --check passed. Runtime checks blocked by absent interpreter; no runtime changes. |
| R0-01 | Verify runtime, isolate test DB, add API baseline checks | `[x]` | Python 3.12.14 local venv; all original direct pins installed; pip check passed; per-test DB and network isolation; 49 tests and actual Uvicorn smoke passed. |
| R0-02 | Enforce dedup hard blocks across both stages/final clusters | `[x]` | Pairwise-safe groups and final checks; host/package/parameter and semantic-bridge regressions; Nessus location preservation; M3-05 resolved. |
| R0-03 | Make rerun/merge/split lifecycle consistent | `[x]` | Stable membership IDs, atomic reconciliation, preserved analyst decisions/history, priority invalidation, case stale flag and audit; rerun/concurrency/rollback tests pass. |
| R0-04 | Correct feed/model provenance and risk explanations | `[x]` | Content-addressed mock cache repository, explicit live rejection, backend/version/input hashes, six risk contributions and labeled neutral validation prior; regression tests pass. |

### Audit decisions

- Source code governs current-state claims; historical checkmarks do not prove present acceptance.
- Existing phases 0-5 contain substantial implementation; validation, cases, dashboard and integration remain unfinished.
- R0 reliability precedes P6 so later case/evidence workflows do not inherit known dedup and persistence gaps.
- Do not claim real exploit confirmation from lab simulation; preserve explicit simulated provenance.
- The user's next-phase condition was not met: instructions/status/plan needed changes, so this session performs documentation work only.

### Verification

- Attempted python -m pytest tests/ -q: command unavailable.
- py --list-paths and py -m pytest tests/ -q: no installed Python found. No tests or startup smoke check passed in this session.
- Source inspection found 21 test functions across five test files and 14 SQLite table definitions.
- Fixture counts verified: 25 + 25 SQLi, 20 + 20 XSS, 10 + 10 SSRF = 110 findings. All local Markdown links in the seven changed documents resolved; git diff --check passed.


## 2026-09-12 R0 Baseline Reliability Completion

User follow-up: "continue". Branch: feature/r0-baseline-reliability. R0-01 through R0-04
are complete. Next: P6 lab validation/evidence using the contract in IMPLEMENTATION_PLAN.md.
The original 79-task baseline now has 53 complete and 26 remaining/deferred; four R0 tasks
are additional and are not folded into that historical count.

### Changes and rationale

- Located bundled CPython 3.12.14 outside PATH/py discovery and created ignored local venv.
  Installed all 12 original direct dependency pins without changing requirements.txt; captured
  resolved versions in requirements-lock.txt for the verified Windows/Python environment.
- Isolated SQLite and model state per test, blocked external connections while permitting
  Windows asyncio loopback IPC, and added API/migration/regression coverage.
- Enforced merge constraints in both stages and final clusters; preserved supplied Nessus
  URL/path/parameter context. Canonical IDs derive from membership; transactions serialize runs.
- Preserved inactive issues, evidence and human decisions. Retiring an issue invalidates its
  priority and marks its case stale. Merge/split actions are repeatable and audited; reviewed
  groups are protected from automatic reruns. Legacy conflicting reviewed groups return 409.
- Moved threat cache SQL into a repository, refreshed mocks by source-content hashes, rejected
  unsupported live mode, labeled hashing fallback and semantic status, hashed input text,
  cleared missing-view vectors, and exposed all six score contributions with a neutral validation prior.

### Verification outcomes

- Clean dependency installation completed under CPython 3.12.14; direct-pin verification: 12/12 match.
- venv/Scripts/python.exe -m pip check: no broken requirements found.
- First regression run: 44 passed, 5 failed because the network fixture blocked Windows
  asyncio's local socketpair. Fixed the fixture to permit literal loopback IPC.
- Final venv/Scripts/python.exe -m pytest tests/ -q: **49 passed in 13.32s**.
  One upstream Starlette/AnyIO deprecation warning remains; no failed or skipped tests.
- Python compilation passed. Actual Uvicorn HTTP smoke returned 200 for /health, /, /docs,
  /openapi.json; health reported 14 tables and mock threat mode. Windows retained the smoke
  server child after parent termination; that child and its isolated temporary directory were cleaned up.
- Documentation links and git diff --check: final verification recorded with this completion.

### Boundaries for the next phase

P6 must implement validation and evidence; the current neutral validation factor is explicitly
not an execution result. P7 must respect cases.stale when assembling/reviewing cases. Cluster
lists retain historical clusters; issue lists show only active issues. Holding a SQLite write
transaction during dedup favors prototype consistency over throughput. Learned-model accuracy,
real Docker execution, live feeds and full P6-P9 integration are not claimed by R0 tests.


## F0 Basic Backend Validation Frontend

| ID | Task | Status | Notes |
|---|---|---|---|
| F0-01 | Build a basic frontend for implemented backend features | `[x]` | Vanilla HTML/CSS/JS console for ingestion, views/embeddings, dedup, cluster review, risk, progress and errors. 49 backend tests plus browser workflow and responsive checks passed. |

### F0 verification

- FastAPI serves the page and local CSS/JavaScript without a CDN or build step.
- Browser automation passed backend health, synthetic JSON import, view extraction, hashing
  fallback embeddings, deduplication, mock-feed prioritization, issue details, and 390px layout.
- `venv/Scripts/python.exe -m pytest tests/ -q`: 49 passed; one upstream Starlette/AnyIO
  deprecation warning. `node --check src/app/static/dashboard.js` and `git diff --check` passed.
- Sandbox validation and case review remain visibly unavailable until P6/P7; F0 does not claim
  the dedicated metrics endpoint or full P8 dashboard as complete.

## 2026-09-12 P6 Lab Validation and Multi-Agent Handoff

This completion section supersedes the unchecked historical M5 rows above. Next phase: P7 cases
and human review. Detailed pickup boundaries are in `docs/AGENT_HANDOFF.md`.

| ID | Status | Completion evidence |
|---|---|---|
| M5-01 | `[x]` | Typed validation request, result and artifact contracts. |
| M5-02 | `[x]` | Offline deterministic SQLi, XSS and SSRF simulation; no target requests or payload execution. |
| M5-03 | `[-]` | Real Docker deferred; requests fail explicitly with HTTP 422. |
| M5-04 | `[x]` | Append-only artifacts with SHA-256 over exact retained UTF-8 bytes. |
| M5-05 | `[x]` | Derived evidence is redacted before persistence and retrieval. |
| M5-06 | `[x]` | Validate, result and evidence APIs return typed responses and correct 404/422 errors. |
| M5-07 | `[x]` | Scenario, timeout, allowlist, Docker, redaction, integrity, persistence and risk tests. |

## 2026-09-12 Core Risk Flow Hardening (feature/core-risk-flow)

| Scope | Status | Verification |
|---|---|---|
| Six-factor risk semantics and validation status mapping | `[x]` | Verified six persisted contributions; simulated match/no-match and inconclusive statuses map to explicit factors (23 focused tests pass). |
| Mock feed provenance and cache failure behavior | `[x]` | Malformed and out-of-range mock feeds raise explicit `ThreatIntelUnavailable`; content fingerprints remain cache keys (23 focused tests pass). |
| Redaction/hash and embedding provenance compatibility | `[x]` | Authorization values are redacted before derived artifacts; artifact metadata records UTF-8 hash basis; learned embeddings include backend package version (23 focused tests pass). |
| DOC-05 | `[x]` | Added handoff-ready critical path with dependencies, file boundaries and acceptance outcomes. |

Verification: `venv/Scripts/python.exe -m pytest tests/ -q` reported **55 passed** with one
upstream Starlette/AnyIO deprecation warning. `pip check` and `git diff --check` passed.


## 2026-09-12 12-Hour Core Feature Execution Backlog

This backlog is the implementation-focused deep dive for the hackathon critical path. It
does not reopen completed M2/M4/M5 foundations; it converts their contracts into reviewable
integration work. Time boxes are estimates, not permission to weaken acceptance criteria.
Tasks over 30 minutes must be split or have a shortcut agreed before implementation.

### Track A - Contextualisation: multi-view extraction and embeddings

| ID | Task | Status | Time box | Acceptance evidence |
|---|---|---|---:|---|
| CTX-01 | Freeze the contextualisation contract across `schemas/views.py`, `extractor.py`, and persistence | `[ ]` | 20m | Four views (`description`, `location`, `reproduction`, `impact`) have explicit missing/partial/available behavior; source fields, confidence, warnings, and extraction method survive a round trip. |
| CTX-02 | Verify defense-in-depth redaction boundaries for derived view text and embedding inputs | `[ ]` | 25m | Bearer/basic auth, cookies, passwords, API keys, and tokens are absent from stored/displayed derived text; raw scanner evidence remains unchanged and separately retrievable. |
| CTX-03 | Verify embedding provenance and compatibility guards | `[ ]` | 25m | Every generated vector records backend/version/dimension and input-text hashes; missing views clear stale vectors; incompatible model provenance returns no similarity instead of silently comparing vectors. |
| CTX-04 | Add a focused contextualisation regression slice for native scanner variants and incomplete evidence | `[ ]` | 30m | Representative SARIF/ZAP/Nessus/manual inputs produce stable views; empty location/reproduction/impact paths are explicit and do not fabricate exploit evidence. |

### Track B - Threat intelligence and prioritization engine

| ID | Task | Status | Time box | Acceptance evidence |
|---|---|---|---:|---|
| TRI-01 | Freeze and verify the six-factor score contract | `[ ]` | 20m | `Risk Score = wcvss*Scvss + wepss*Sepss + wkev*Skev + wasset*Sasset + wnet*Snet + wval*Sval`; configured weights sum to 1, normalized factors are bounded, and the API exposes every contribution. |
| TRI-02 | Verify threat-feed provenance, cache freshness, and failure behavior | `[ ]` | 25m | KEV/EPSS mock results include source fingerprints and timestamps; changed mock content invalidates cache; malformed/missing feeds and live-mode flags fail explicitly rather than becoming clean results. |
| TRI-03 | Verify prioritization decisions and explanations against analyst-readable scenarios | `[ ]` | 30m | KEV or score >=80 produces Immediate, score >=50 produces Accelerated, otherwise Standard; no-CVE findings remain valid; explanations identify factors, weights, contributions, and mock-data limitations. |
| TRI-04 | Add a focused prioritization regression slice after validation state changes | `[ ]` | 25m | Latest validation status changes only `Sval` and its recorded explanation; reprioritization is explicit after feed or membership changes; retired issues cannot receive a new priority. |

### Track C - Sandbox validation and immutable evidence

| ID | Task | Status | Time box | Acceptance evidence |
|---|---|---|---:|---|
| SBX-01 | Freeze the validation/evidence contract and human-safety gates | `[ ]` | 20m | Lab simulator is the default; target hosts must be allowlisted; unsupported scenarios/timeouts are inconclusive; submitted scanner payloads are never executed; Docker remains rejected by default. |
| SBX-02 | Verify immutable artifact retention and derived-artifact sanitization | `[ ]` | 25m | Validation runs/artifacts are append-only; redaction occurs before persistence/display; SHA-256 covers the exact retained UTF-8 bytes; retrieval recomputes and verifies the hash. |
| SBX-03 | Verify validation-to-risk semantics without claiming exploitability | `[ ]` | 25m | `simulated_match`, `simulated_no_match`, and `inconclusive` map to explicit validation factors; explanations say simulation does not prove exploitability; raw evidence and derived artifacts remain distinguishable. |

### Track D - 12-hour integration and analyst handoff

| ID | Task | Status | Time box | Depends on | Acceptance evidence |
|---|---|---|---:|---|---|
| FLOW-01 | Implement one repeatable vertical-flow checklist: ingest -> views -> embeddings -> dedup -> prioritize -> simulate -> case input | `[ ]` | 30m | CTX-01, TRI-01, SBX-01 | A synthetic SQLi/XSS/SSRF finding can be followed by ID through each stage with source provenance, status labels, and no hidden fallbacks. |
| FLOW-02 | Add case-review boundary checks before any dashboard work | `[ ]` | 25m | FLOW-01 | No service auto-approves/rejects a case; analyst actor and reason are required for decisions; stale/retired issue references are surfaced rather than silently reused. |
| FLOW-03 | Run the smallest end-to-end verification set and record blockers honestly | `[ ]` | 30m | FLOW-01, FLOW-02 | Targeted tests plus API smoke cover one happy path, one redaction path, one feed failure, one inconclusive validation, and one prohibited Docker request; results are logged here. |

### Task creation completion note

- Added a time-boxed backlog for contextualisation, threat intelligence/prioritization, sandbox
  evidence, and the integrated analyst flow.
- Anchored tasks to the existing service/repository separation instead of duplicating completed
  M2, M4, and M5 implementation rows.
- Made the six-term risk formula, provenance requirements, immutable evidence rules, and human
  approval boundary explicit acceptance criteria.
- No runtime code, secrets, schema contracts, or environment files were changed in this planning
  pass; implementation tasks remain `[ ]` until their checks are actually run.

## 2026-09-12 Debug verification (feature/debug-verification)

| Scope | Status | Evidence |
|---|---|---|
| Case handoff stale refresh | `[x]` | Fixed stale snapshot regeneration to reuse the existing case row identity; added `test_stale_case_refresh_preserves_retrievable_case_identity`. |
| Contextualisation/risk/validation/case regression slice | `[x]` | `venv\\Scripts\\python.exe -m pytest tests\\test_extractor.py tests\\test_risk_engine.py tests\\test_validation.py tests\\test_cases.py -q`: 17 passed. |
| Full regression suite | `[x]` | `venv\\Scripts\\python.exe -m pytest tests\\ -q`: 57 passed, 2 skipped; two existing Starlette/AnyIO deprecation warnings. |
| Runtime/API smoke | `[x]` | `venv\\Scripts\\python.exe -m pip check`: no broken requirements; `compileall -q src tests`; Uvicorn `GET /health` and `GET /openapi.json`: 200/200; `git diff --check` passed. |

Blocker: the root `AGENT_HANDOFF.md` path referenced by the task was absent; the available handoff at `docs/AGENT_HANDOFF.md` was read instead. Unrelated `src/app/parsers/__init__.py`, `data/pipeline_testing_guide.md`, and `data/sample_upload.json` changes were preserved and not included in this debug commit.

## 2026-09-12 Frontend feature access (feature/frontend-feature-access)

| Scope | Status | Evidence |
|---|---|---|
| Analyst access layer | `[x]` | Reworked the static page to expose ingestion, four views, embedding provenance, dedup clusters, six-factor risk contributions/mock labels, offline validation limitations, case queue/detail, required actor/reason review actions, and per-case audit timeline. |
| Graceful states and safety labels | `[x]` | Loading/unavailable/error and empty states remain visible; UI states that simulation is inconclusive evidence and Docker execution is disabled. Raw evidence is distinguished from escaped derived display text. |
| Frontend/backend validation | `[x]` | `node --check src\\app\\static\\dashboard.js`, `git diff --check`, and `venv\\Scripts\\python.exe -m pytest tests\\test_validation.py tests\\test_cases.py -q` passed (9 passed, 2 existing deprecation warnings). Backend services and unrelated working-tree files were not modified. |
## 2026-09-12 Evidence integrity hardening (feature/remaining-core-essentials)

- Added repository-side SHA-256 and UTF-8 byte-size validation before saving artifacts.
- Added retrieval verification and an API 500 integrity failure response so tampered evidence is never served.
- Added a regression test that mutates persisted evidence and verifies direct retrieval and the HTTP evidence endpoint reject it.
- Verification: `venv\\Scripts\\python.exe -m pytest tests\\test_validation.py -q`  8 passed.
- Real Docker execution, live feeds, and orchestration remain deferred; no unverified capability is marked complete.

## Final integration verification  `feature/final-15min-verification` (2026-09-12)

- Created from `feature/hackathon-verification` without modifying `main`.
- Integrated completed evidence integrity commit `3833d09` (`feature/remaining-core-essentials`), with case-query and frontend case-inspection work already present through the hackathon branch ancestry, and merged completed `feature/context-completion-guardrails` (`232d1ba`, `48aa360`). No real merge conflicts occurred.
- Preserved unrelated user files in pre-existing stashes; they were not included in the integration commit.
- Verification: `venv\Scripts\python.exe -m pytest tests\ -q`  60 passed, 2 skipped; `venv\Scripts\python.exe -m pip check`  no broken requirements; `node --check src\app\static\dashboard.js` passed; `git diff --check` passed.
- Uvicorn on `127.0.0.1:8000`: `/`, `/health`, and `/openapi.json` returned 200; `/api/v1/cases` returned 200; a nonexistent evidence resource returned expected 404. Server stopped after checks.
- Deferred explicitly: live feeds, Docker execution, orchestration, Slack/Jira integrations, polling, and webhooks. Simulations remain labeled/mock and Docker-disabled; human analysts retain final review authority.
| F1-DEMO-01 | `[x]` | Replaced analyst JSON/file/manual inputs with a fixed six-export, 110-finding synthetic catalog. |
| F1-DEMO-02 | `[x]` | Added safe catalog/load and real metrics APIs; unknown dataset IDs cannot access arbitrary files. |
| F1-DEMO-03 | `[x]` | Added interactive module stages, evidence explorer, risk details and offline validation artifacts. |
| F1-DEMO-04 | `[x]` | Added responsive warm-neutral visual system with no external assets or build step. |
| F1-DEMO-05 | `[x]` | Aligned UI with `design.md`: editorial type, ink pills, soft cards, hairlines and pastel atmosphere. |
| F1-DEMO-06 | `[x]` | Increased pastel depth across dataset, metric, pipeline and modal surfaces while preserving contrast and ink CTAs. |
| F1-DEMO-07 | `[x]` | Deepened pastel visibility and bundled the open Doto display font for selected N-Dot-style headings. |
| F1-DEMO-08 | `[x]` | Applied the requested sage/ivory/cream/tan palette and Claimcheck-first number styling with local Doto fallback. |
| DOC-06 | `[x]` | Added `docs/design.md`, translating the visual reference into complete project screens, states, trust language and accessibility rules. |
| UX-PLAN-01 | `[x]` | Added `docs/FEATURE_UX_PLAN.md`: per-feature layouts/actions/API gates, minimal-effort sequence, change handling and service audit. Live read endpoints on port 8001 returned 200; case/review remain stubs. Preserved the user's local edit to docs/design.md. |
| UX-A-01 | `[x]` | Fixed startup parser registration, SARIF demo dispatch and Burp SSRF mapping; atomic content-addressed imports preserve scanner identity and raw sources. UI distinguishes new/already-loaded findings. All 110 fixtures, repeat/concurrent load and rollback/retry tested. |

UX-A verification: 60 tests passed in 70.43s with a test-process-only AMD64 architecture stub to
avoid Windows WMI native errors; normal test invocations were interrupted by native errors and
are not recorded as passes. One upstream Starlette warning remains. JS syntax/diff checks passed.
Restarted backend on port 8001 with 14 tables healthy. User's local docs/design.md edit preserved.
Next: increment B shared feature navigation and detail UX; cases/review remain planned.

Verification: 56 tests passed, JavaScript syntax and `git diff --check` passed. The configured
in-app/extension browser list was empty, so rendered browser automation was unavailable in this run.

## 2026-09-12 D1 Data Corpus Expansion (Snyk + Trivy + Threat Intel)

Branch: feature/D1-expand-data-corpus.

Added two new scanner fixture files and expanded both threat-intel mock feeds so the data folder
covers all four supported scanner types (Nessus, Burp, Snyk, Trivy) referenced in the product
requirements and parsers already implemented in M1.

| ID | Task | Status | Evidence / result |
|---|---|---|---|
| D1-09 | Add `data/snyk_sca.json` — 15 Snyk SCA findings | `[x]` | 15 realistic SCA findings covering Log4Shell, Spring4Shell, Text4Shell, OpenSSL, Django SQLi, and more across maven/npm/pip/rubygems package managers. All fields match SnykParser field expectations. |
| D1-10 | Add `data/trivy_container.json` — 15 Trivy container scan findings | `[x]` | 15 findings across 5 container image targets (auth-service, api-gateway, web-frontend, payment-service, ml-pipeline, etc.) with both `library` and `os` type entries. All fields match TrivyParser field expectations. |
| D1-11 | Expand `data/cisa_kev_mock.json` from 5 to 12 entries | `[x]` | Added Log4j2 (CVE-2021-45046), Spring4Shell, Text4Shell, OpenSSL, HTTP/2 Rapid Reset, Apache mod_proxy smuggling, SnakeYaml, and Django SQL Injection entries. Updated count and catalogVersion. |
| D1-12 | Expand `data/epss_mock.json` from 7 to 30 entries | `[x]` | Added EPSS scores for all CVEs referenced across the full corpus (SQLi CVE-2024-10xx, XSS CVE-2024-20xx, Snyk SCA CVEs, and Trivy container CVEs) with realistic EPSS scores and percentiles. |
| D1-13 | Update `data/README.md` with full corpus inventory | `[x]` | Corpus table, dedup test design notes, and scanner data notes for all 8 fixture files and 2 threat-intel feeds. |
| D1-14 | Fix `scratch/generate_datasets.py` DATA_DIR to use repo-relative path | `[x]` | Replaced hardcoded Windows path `c:\Users\harsh\...` with `os.path.join(os.path.dirname(__file__), "..", "data")`. Added Snyk SCA and Trivy container sections. |

### D1 expansion totals

- Scanner fixture files: 8 total (was 6)
- Total scanner findings: 140 (was 110; +15 Snyk SCA, +15 Trivy container)
- CISA KEV entries: 12 (was 5; +7 real-world exploited CVEs)
- EPSS entries: 30 (was 7; covers every CVE in the full corpus)
- Data README: updated with corpus table and dedup test-design documentation

Cross-scanner dedup test coverage in new files:
- Log4j CVE-2021-44228 appears in both snyk_sca.json and trivy_container.json on **different** container
  targets — these must remain separate (different asset identities).
- No new cross-scanner merge pairs were introduced; existing SQLi/XSS/SSRF overlaps unchanged.
