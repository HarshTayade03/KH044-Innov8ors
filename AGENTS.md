# Agent Instructions — AI-Assisted Vulnerability Triage Platform

> **Public name:** AI-Assisted Vulnerability Triage Platform
> **Internal name:** VulnTriager (never use this in public-facing materials)
> **Last updated:** 2026-09-12
>
> Read this file completely before touching any code. Then read `TASK_LOG.md` for current task
> status and `docs/PROJECT.md` for the full technical and product reference.

---

## 1. Non-negotiable rules

These apply unconditionally to every agent, contributor, and session.

| Rule | Detail |
|---|---|
| **Never commit directly to `main`** | Always work on a `feature/<task-id>-<description>` branch |
| **No secrets in code or commits** | All credentials live in `.env`; never read or write `.env` without explicit user authorization |
| **Simulated ≠ real exploitability** | Label all sandbox/simulation output as simulated; scanner findings are *reported*, not confirmed |
| **Human approval is final** | No automated action may approve, reject, or override a case decision |
| **Preserve original evidence** | Raw scanner data is immutable; store derived/redacted artefacts separately with SHA-256 hashes |
| **Sandbox disabled by default** | `SANDBOX_ENABLED=false`; real Docker execution is deferred; configured allowlist required before any lab request |
| **Inspect before editing** | Read existing code/schema/spec before claiming anything about it |
| **Honest reporting** | Distinguish implemented, verified, partial, and planned work; never mask failures |

---

## 2. Architecture

```
src/app/
├── main.py          FastAPI entry point — registers all routers under /api/v1
├── config.py        pydantic-settings; reads .env; validates risk weight sums at startup
├── database.py      SQLite — 14 tables; WAL mode + FK constraints; migrations are additive
├── api/             One router file per feature area (ingestion, findings, clusters, cases…)
├── parsers/         Stateless scanner parsers: nessus, burp, sarif, zap, snyk, trivy
├── schemas/         Pydantic v2 models — the contract layer; change only with all consumers
├── services/        Business logic — call repositories; never touch DB directly
├── repositories/    All SQL — multi-table writes use database.transaction()
├── static/          Single-file frontend: index.html + dashboard.css + dashboard.js (no build step)
└── workers/         Background task stubs (scanner poller raises NotImplementedError)
```

**Layer rules:**
- **Schemas are contracts.** Any schema change must update every producer and consumer together.
- **Services own logic.** They call repositories; they have no direct DB access.
- **Repositories own SQL.** Multi-table writes use `database.transaction()` for atomic commits.
- **Parsers are stateless.** Each parser translates one raw record. The `NormalizerService` builds the final schema.
- **Frontend is no-build.** A single HTML/CSS/JS file served by FastAPI; no npm, no bundler.

**Database:** 14 tables — findings, batches, views, embeddings, canonical_issues, clusters, cluster_members, risk_scores, threat_intelligence, validation_runs, artifacts, cases, reviews, audit_events. Additive migrations preserve existing databases.

**Routing:** `/`, `/health`, `/docs` are root routes. All feature routes are under `/api/v1`.

---

## 3. Working conventions

### Branch naming
```
feature/<task-id>-<description>
fix/<task-id>-<description>
docs/<task-id>-<description>
```

### Commit format
```
[task-id] type: short imperative summary (≤72 chars)

Optional body — WHY, not just what the diff shows.
```
Types: `feat` · `fix` · `docs` · `data` · `test` · `refactor` · `style` · `chore`

### Task workflow
1. Mark your task `[/]` in `TASK_LOG.md` before starting.
2. Read existing code/spec in the relevant module before editing.
3. One logical concern per commit.
4. Run tests; mark `[x]` only after they pass.
5. Mark `[!]` + blocker note if blocked; do not skip ahead.
6. If work exceeds 30 minutes, split into reviewable increments and push a draft PR.

### Before starting any module
Read the relevant spec in `docs/MODULE_SPECS/` if one exists. If no spec exists, write the contract and acceptance criteria first — do not implement a module without a spec.

---

## 4. Runtime and verification

### Setup (run from repo root)
```bash
python -m venv .venv
source .venv/bin/activate           # macOS/Linux
# .venv\Scripts\Activate.ps1        # Windows

pip install -r requirements.txt
pip check                           # must report no broken requirements
cp .env.example .env
python -m uvicorn src.app.main:app --reload --port 8000
```

The bundled Python is 3.12.14. Do **not** change pinned versions in `requirements.txt` without a specific compatibility reason. `requirements-lock.txt` records the tested transitive closure for Python 3.12/Windows x64.

### Tests
```bash
python -m pytest tests/ -q          # full suite — must pass before any PR
python -m pytest tests/test_X.py -v # focused regression for the changed module
pip check                           # after any dependency change
```

Tests use one isolated SQLite database per test, deterministic SHA-256 hashing (not a downloaded model), and a network fixture that blocks external sockets (loopback IPC is allowed for Windows asyncio).

### Smoke check
After startup, verify:
- `GET /health` → HTTP 200, `"tables": 14`, `"threat_mode": "mock"`
- `GET /docs` → interactive OpenAPI UI loads
- `POST /api/v1/findings/upload` with a fixture file → valid `BatchSummary`

**Record actual outcomes in `TASK_LOG.md`.** Historical pass claims in the log do not prove present acceptance.

---

## 5. Key implementation details

### Fingerprinting
```python
# SHA-256(cwe_root | canonical_path | parameter_class)
# CWE children resolve via CWE_PARENT_MAP before hashing:
#   CWE-564 → CWE-89, CWE-80 → CWE-79, CWE-81/85/86/87 → CWE-79
compute_fingerprint(cwe_primary, url_or_path, parameter_class)
```

### Deduplication (two stages)
- **Stage A (deterministic):** groups by fingerprint; hard-block merges if different host/package/parameter class.
- **Stage B (semantic):** HDBSCAN on cosine distance matrix from weighted view embeddings; same hard-block rules apply.
- **Lifecycle:** canonical IDs are stable (derive from sorted membership); reruns are idempotent; reviewed groups are protected; legacy conflicts return 409.

### Embeddings
- Primary: `SentenceTransformer` (requires model download; opt-in via `MODEL_ALLOW_DOWNLOAD=true`).
- Fallback: pure Python SHA-256 token hashing (always available; labeled `"hashing"` — not semantic evidence).
- Store backend name, version, dimension, and input-text hash. Do not compare vectors from different backends.

### Risk scoring
Composite score 0–100: `CVSS × w_cvss + EPSS × w_epss + KEV_flag × w_kev + asset_criticality × w_asset + network_exposure × w_net + validation_prior × w_val`. All six contributions are itemized in the explanation. Weights are configurable in `.env` and validated to sum to 1.0 at startup.

Tiers: **Immediate** (KEV or score ≥ 80) · **Accelerated** (score ≥ 50) · **Standard** (otherwise).

### Threat feeds
Only mock feeds are implemented. `cisa_kev_mock.json` and `epss_mock.json` in `data/` are the sources. Cache is refreshed by content hash. Live mode (`THREAT_INTEL_LIVE=true`) returns HTTP 503 with an explicit error.

### Validation (M5)
Deterministic offline simulator for SQLi, XSS, SSRF scenarios. Results are labeled `simulated_match`, `simulated_no_match`, or `inconclusive` — never "confirmed exploitable". Artefacts are append-only with SHA-256 over exact retained UTF-8 bytes. Real Docker is rejected explicitly when `SANDBOX_ENABLED=true`.

### CVE / CWE normalisation
- CVE: `"cve 2024 1234"`, `"CVE_2024_1234"`, URLs → `"CVE-2024-1234"`; invalid patterns are dropped.
- CWE: bare integers (`89`), `"CWE89"` → `"CWE-89"`; child CWEs resolve to root via `CWE_PARENT_MAP`.
- Severity: non-canonical values (`"URGENT"`) → `"Unknown"` with a warning.
- CVSS outside 0–10 → `null` with a warning.

---

## 6. What is implemented vs. planned

| Phase | Status | Notes |
|---|---|---|
| M0 — Bootstrap, config, 14-table DB | ✅ Done | Health route, 6 routers registered |
| M1 — Parsers and normalization | ✅ Done | nessus, burp, sarif, zap, snyk, trivy |
| D1 — Synthetic data corpus | ✅ Done | 140 findings, 8 fixture files, 2 mock feeds |
| M2 — 4-view extraction + embeddings | ✅ Done | Description/Location/Reproduction/Impact; hashing fallback |
| M3 — Deduplication + lifecycle | ✅ Done | Stage A fingerprint + Stage B HDBSCAN; merge/split; idempotent reruns |
| M4 — Threat intel + risk scoring | ✅ Done | Mock KEV/EPSS cache; composite score; tier assignment |
| M5 — Offline validation + evidence | ✅ Done | SQLi/XSS/SSRF simulation; immutable artefacts; SHA-256 integrity |
| F1 — Demo frontend | ✅ Done | Synthetic-corpus console; 6 datasets; pipeline stages; evidence explorer |
| M6 — Cases and human review | 🔲 Next | Schema stub only; assembly, state machine, audit log not started |
| M7 — Case review dashboard | 🔲 Planned | Depends on M6 APIs |
| P9 — Orchestration + full pipeline | 🔲 Planned | Per-stage counts, retry, 110-finding end-to-end test |
| P10 — External integrations | 🔲 Deferred | Real Docker, live feeds, Slack, Jira, webhooks |

**49 backend tests + 6 demo/validation tests pass.** Live fetching, Docker, cases, and dashboard metrics remain unimplemented.

---

## 7. Scope boundaries

**In scope for the prototype:**
- Reliable local ingestion, normalization, deduplication, prioritization, and offline validation.
- Human analyst review controls with mandatory actor/reason and append-only audit log (M6).
- Single-page frontend served by FastAPI with no external dependencies.

**Permanently deferred (do not implement without explicit user instruction):**
- Real Docker sandbox execution.
- Live CISA KEV / EPSS / NVD API calls.
- Scanner polling webhooks.
- Slack / Jira integrations.

---

## 8. Data files

Scanner fixtures in `data/` — see `data/README.md` for the full corpus table. Scanner format field references are in `docs/PROJECT.md §8`. When adding a fixture: name it `<scanner>_<type>.json`, update `data/README.md`, and add a row to `TASK_LOG.md`. Never commit credentials, real production IPs, or real PII to `data/`.
