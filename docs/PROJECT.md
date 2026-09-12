# Project Knowledge — AI-Assisted Vulnerability Triage Platform

> Single reference for product intent, technical architecture, module status, data corpus,
> scanner formats, design system, and roadmap. Keep this file in sync with `TASK_LOG.md`
> and `docs/MODULE_SPECS/` as the project evolves.
>
> **Last updated:** 2026-09-12

---

## 1. Problem statement

Security teams receive hundreds or thousands of raw vulnerability findings from multiple scanners,
threat feeds, and manual reports. These findings arrive in different formats, use inconsistent
naming, and often describe the same underlying issue multiple times. Analysts must manually
normalise data, identify duplicates, verify genuineness, and decide which vulnerabilities to
address first.

**This platform automates the triage pipeline while keeping human analysts in control of every
final decision.**

### Evaluation criteria

- **Triage accuracy** — correct grouping and priority assignment.
- **Evidence integrity** — original scanner data preserved; derived artefacts hashed.
- **Prioritization quality** — risk score reflects real-world exploitability signals.
- **Safety** — simulated outcomes never claimed as real; Docker sandbox off by default.
- **Analyst value** — cases are actionable; approval/rejection is human-controlled.

---

## 2. Product overview

```
Nessus / Rapid7 ──┐
Burp Suite ────────┤
Snyk ──────────────┤  → Normalization → 4-View Extraction → Embeddings
Trivy ─────────────┘                                          ↓
OWASP ZAP ─────────────────────────────────────────    AI Deduplication
                                                              ↓
                                                     Offline Sandbox Validation
                                                              ↓
                                                    Threat Intelligence + Risk Score
                                                              ↓
                                                       Case Generation
                                                              ↓
                                                       Human Review ✓
```

### Core principles

1. Preserve original scanner data immutably.
2. One unified internal finding schema for all sources.
3. Never invent missing technical information.
4. Keep reported, inferred, and validated information separate.
5. Scanner alerts are *findings*, not automatically confirmed vulnerabilities.
6. Run potentially dangerous PoC only inside an isolated sandbox.
7. Every automated decision must be explainable.
8. Human analysts retain final approval authority.

---

## 3. End-to-end pipeline

### 3.1 Workflow stages

| Stage | Description |
|---|---|
| 1. Input & Normalization | Receive findings from Nessus/Rapid7/Burp/Snyk/Trivy/ZAP; parse; map to unified schema |
| 2. Multi-View Extraction | Split each finding into Description, Location, Reproduction, Impact views |
| 3. Embedding Generation | Sentence Transformer (or SHA-256 token hashing fallback) per view |
| 4. Deduplication | Stage A: fingerprint groups; Stage B: HDBSCAN semantic clustering; merge into canonical issues |
| 5. Sandbox Validation | Deterministic offline SQLi/XSS/SSRF simulation; immutable evidence with SHA-256 hashes |
| 6. Threat Intelligence | CISA KEV lookup; EPSS score; cached in SQLite by content hash |
| 7. Risk Prioritization | Composite 0–100 score; Immediate / Accelerated / Standard tiers |
| 8. Case Generation | Assemble canonical issue + findings + views + risk + validation refs *(M6 — planned)* |
| 9. Human Review | Analyst approves/rejects; actor + reason required; append-only audit log *(M6 — planned)* |

### 3.2 State machine

```
RECEIVED → NORMALIZED / NORMALIZED_WITH_WARNINGS / REJECTED
         → VIEWS_EXTRACTED → EMBEDDINGS_GENERATED
         → CLUSTERED / CANONICALIZED
         → VALIDATION_PENDING → CONFIRMED / NOT_EXPLOITABLE / INCONCLUSIVE (all simulated)
         → RISK_PRIORITIZED → CASE_GENERATED
         → ANALYST_APPROVED / ANALYST_REJECTED
```

---

## 4. Module inventory and status

> ✅ Implemented and tested · 🔲 Planned · ➖ Deferred

| Module | Key files | Status | Notes |
|---|---|---|---|
| **M0** Bootstrap | `main.py`, `config.py`, `database.py` | ✅ | 14 tables, 6 routers, health route, WAL + FK |
| **M1** Ingestion & parsers | `schemas/canonical.py`, `parsers/`, `services/normalizer.py`, `api/ingestion.py`, `repositories/findings_repo.py` | ✅ | Upload, direct JSON, manual API; CVE/CWE/severity normalisation; fingerprinting; quality scoring |
| **D1** Synthetic data | `data/` (8 fixture files) | ✅ | 140 findings across 6 scanner types + 2 mock threat-intel feeds |
| **M2** Views & embeddings | `schemas/views.py`, `services/extractor.py`, `services/embedding.py`, `api/findings.py` | ✅ | 4 views; redaction; SentenceTransformer or SHA-256 hashing; weighted cosine similarity |
| **M3** Deduplication | `schemas/dedup.py`, `services/deduplicator.py`, `repositories/dedup_repo.py`, `api/clusters.py` | ✅ | Stage A fingerprint + Stage B HDBSCAN; hard-block merge rules; stable IDs; idempotent reruns |
| **M4** Threat intel & risk | `schemas/risk.py`, `services/risk_engine.py`, `services/threat_intel.py`, `repositories/risk_repo.py`, priority routes in `api/cases.py` | ✅ | Mock KEV/EPSS; composite 0–100 score; 3 tiers; 6-contribution explanations |
| **M5** Validation & evidence | `schemas/validation.py`, `services/sandbox.py`, `repositories/validation_repo.py`, `api/validation.py` | ✅ | SQLi/XSS/SSRF offline simulation; allowlist; immutable redacted artefacts; SHA-256 hashes |
| **M6** Cases & review | DB tables `cases`, `reviews`, `audit_events`; `schemas/case.py` | 🔲 | Schema stub + 7 HTTP 501 routes; no assembly, state machine, or audit implementation |
| **F1** Demo frontend | `static/index.html`, `dashboard.css`, `dashboard.js` | ✅ | Synthetic-corpus dashboard; 6 fixture datasets; pipeline stages; cluster/evidence/risk explorer |
| **M7** Dashboard metrics | `api/dashboard.py` | 🔲 | Dedicated metrics API is HTTP 501; case queue and audit timeline await M6 |
| **P9** Orchestration | — | 🔲 | No pipeline orchestrator; stages require separate API calls |
| **P10** External integrations | `workers/scanner_poller.py` | ➖ | Poller raises `NotImplementedError`; Slack/Jira/webhooks absent |

**Verified test counts:** 49 backend unit tests + M5/demo tests pass. 14 SQLite tables. Real Uvicorn smoke checks pass.

---

## 5. API surface

All feature routes: `/api/v1`. Root routes: `/`, `/health`, `/docs`.

| Group | Routes |
|---|---|
| Ingestion | `POST /findings/upload`, `POST /findings`, `POST /findings/manual` |
| Findings | `GET /findings`, `GET /findings/{id}`, `POST /findings/{id}/extract-views`, `POST /batches/{id}/extract-views`, `GET /findings/{id}/views`, single/batch embedding routes |
| Deduplication | `POST /deduplication/run`, `GET /clusters`, `GET /clusters/{id}`, `GET /canonical-issues`, `GET /canonical-issues/{id}`, merge/split |
| Priority | `POST /canonical-issues/{id}/prioritize`, `GET /priorities`, `GET /priorities/{id}` |
| Validation | `POST /canonical-issues/{id}/validate`, `GET /validation-runs/{id}`, evidence retrieval |
| Stubs (501) | Case generation, case review, dashboard metrics |

### Batch response schema
```json
{
  "batch_id": "uuid",
  "source_scanner": "nessus",
  "total_received": 25,
  "normalized": 23,
  "normalized_with_warnings": 2,
  "rejected": 0,
  "status": "completed",
  "next_stage": "multi_view_extraction"
}
```

---

## 6. Normalised finding schema

```json
{
  "finding_id": "f-uuid",
  "source_scanner": "burp",
  "source_finding_id": "burp-ssrf-001",
  "ingestion_batch_id": "batch-uuid",
  "ingested_at": "2026-09-12T10:00:00Z",
  "vulnerability": {
    "cve_ids": [],
    "cwe_ids": ["CWE-918"],
    "title": "Server-Side Request Forgery in /api/fetch",
    "description": "...",
    "severity": "High",
    "cvss_score": 8.6,
    "confidence": "Certain"
  },
  "asset": {
    "asset_name": "app.example.test",
    "asset_type": "web_application",
    "environment": "lab",
    "internet_facing": false,
    "criticality": "high"
  },
  "location": {
    "host": "app.example.test",
    "port": null,
    "protocol": "https",
    "url": "https://app.example.test/api/fetch",
    "path": "/api/fetch",
    "parameter": "url"
  },
  "evidence": {
    "summary": "AWS metadata endpoint returned credentials.",
    "request": "POST /api/fetch ...",
    "response": "HTTP/1.1 200 OK ...",
    "raw_output": "..."
  },
  "remediation": { "recommendation": "...", "fixed_version": null, "reference_urls": [] },
  "provenance": {
    "source_file": "burp_ssrf.json",
    "parser_name": "BurpParser",
    "parser_version": "1.0.0",
    "raw_record_hash": "sha256:...",
    "original_data": {}
  },
  "quality": {
    "normalization_status": "normalized",
    "completeness_score": 0.92,
    "warnings": [],
    "errors": []
  }
}
```

---

## 7. Data corpus

| File | Scanner | Format | Vuln type | Count |
|---|---|---|---|---|
| `burp_sqli.sarif` | Burp Suite Pro | SARIF 2.1.0 | SQL Injection | 25 |
| `nessus_sqli.json` | Nessus / Rapid7 | JSON | SQL Injection | 25 |
| `burp_xss.sarif` | Burp Suite Pro | SARIF 2.1.0 | Cross-Site Scripting | 20 |
| `zap_xss.json` | OWASP ZAP | JSON | Cross-Site Scripting | 20 |
| `burp_ssrf.json` | Burp Suite | JSON | SSRF | 10 |
| `nessus_ssrf.sarif` | Nessus | SARIF 2.1.0 | SSRF | 10 |
| `snyk_sca.json` | Snyk | JSON | SCA / Dependency CVEs | 15 |
| `trivy_container.json` | Trivy | JSON | Container / OS CVEs | 15 |
| `rapid7_insightvm.json` | Rapid7 InsightVM | JSON | Mixed (RCE, SQLi, XSS…) | 10 |
| `nessus_edge_cases.json` | Nessus | JSON | Edge cases for normalization testing | 10 |

**Mock threat-intel feeds:** `cisa_kev_mock.json` (12 KEV entries) · `epss_mock.json` (30 EPSS scores)

### Cross-scanner dedup test design
- First 5 Nessus SQLi records match first 5 Burp SQLi records (same host + path + parameter → should merge).
- First 8 ZAP XSS records match first 8 Burp XSS records (same path + parameter → should merge).
- First 3 Nessus SSRF records match first 3 Burp SSRF records (same path + parameter → should merge).
- Log4j CVE-2021-44228 in Snyk and Trivy fixtures targets **different container images** → must stay separate.

Validation tool: `python scratch/validate_data.py`

---

## 8. Scanner input formats

### 8.1 Nessus / Rapid7 InsightVM — `source_scanner = "nessus"`

JSON array. Rapid7 InsightVM exports use identical field names.

| Field | Type | Notes |
|---|---|---|
| `plugin_id` | integer | `source_finding_id` |
| `plugin_name` | string | `title`; used for CWE inference if no explicit CWE |
| `host` | string | Also accepts `hostname`, `ip` |
| `severity` | string | Critical / High / Medium / Low / Informational |
| `cve` | string\|list | Normalised to `CVE-YYYY-NNNNN` |
| `cvss_base_score` | float | Valid 0–10; out-of-range → null + warning |
| `url`, `path`, `parameter` | string | Optional web context for cross-scanner dedup |

### 8.2 Burp Suite Pro — `source_scanner = "burp"`

Flat JSON array (not SARIF). SARIF from Burp uses the `sarif` parser.

| Field | Type | Notes |
|---|---|---|
| `issue_id` | string | `source_finding_id` |
| `name` | string | `title` |
| `host` | string | Full URL or hostname |
| `path`, `parameter` | string | Web context |
| `issue_background` | string | `description` |
| `request`, `response`, `evidence` | string | Evidence fields; Authorization headers are redacted |

### 8.3 OWASP ZAP — `source_scanner = "zap"`

JSON array. `riskcode` is a string `"0"–"3"` (not a CVSS float).

| `riskcode` | Severity |
|---|---|
| `"3"` | High |
| `"2"` | Medium |
| `"1"` | Low |
| `"0"` | Informational |

Fields: `alertRef` (id), `alert` (title), `url`, `param`, `attack`, `evidence`, `cweid`.

### 8.4 SARIF 2.1.0 — `source_scanner = "sarif"`

```json
{
  "version": "2.1.0",
  "runs": [{ "tool": {...}, "results": [
    {
      "ruleId": "sqli",
      "level": "error",
      "locations": [{ "physicalLocation": { "artifactLocation": {"uri": "..."} } }],
      "properties": { "host": "...", "path": "...", "parameter": "...",
                      "request": "...", "response": "...", "cve_ids": ["CVE-…"] }
    }
  ]}]
}
```

SARIF `level` → severity: `error` = High · `warning` = Medium · `note` = Low

Burp `ruleId` → CWE: `sqli` = CWE-89 · `xss` = CWE-79 · `ssrf` = CWE-918 (see `BURP_RULE_TO_CWE` in `parsers/base.py`)

### 8.5 Snyk SCA — `source_scanner = "snyk"`

JSON array from `snyk test --json`.

| Field | Type | Notes |
|---|---|---|
| `id` | string | `source_finding_id` |
| `package_name` | string | Also `pkgName`, `packageName` |
| `cve` | string\|list | CVE(s) |
| `cwe` | string\|list | CWE(s) |
| `fixed_in` | list | Fixed version(s) |
| `file`, `package_manager`, `from` | string | Manifest and dependency chain |

### 8.6 Trivy — `source_scanner = "trivy"`

JSON array from `trivy image --format json`. Accepts both snake_case and PascalCase.

| Field | Type | Notes |
|---|---|---|
| `vulnerability_id` / `VulnerabilityID` | string | CVE or GHSA ID; used as `source_finding_id` |
| `pkg_name` / `PkgName` | string | Package name |
| `target` / `Target` | string | Container image (e.g. `"auth-service:2.1.0"`) |
| `type` / `Type` | string | `"os"` or `"library"` |
| `cwe_ids` / `CweIDs` | list | CWE IDs |

### 8.7 Normalisation rules (all parsers)

| Input | Rule |
|---|---|
| CVE variants | `"cve 2024 1234"`, `"CVE_2024_1234"` → `"CVE-2024-1234"`; invalid → dropped |
| CWE variants | `89`, `"CWE89"` → `"CWE-89"`; children resolve via `CWE_PARENT_MAP` |
| Severity | Non-canonical strings → `"Unknown"` + warning |
| CVSS out of range | Values < 0 or > 10 → `null` + warning |
| Non-numeric port | String port values → `null` + warning |
| Completeness | Fraction of 7 required fields present (0.0–1.0) |

---

## 9. Risk scoring

**Composite score formula (0–100):**

```
score = (CVSS/10 × w_cvss + EPSS × w_epss + KEV_flag × w_kev
        + asset_criticality × w_asset + net_exposure × w_net
        + validation_prior × w_val) × 100
```

Default weights (`config.py`): CVSS=0.35, EPSS=0.25, KEV=0.20, asset=0.10, exposure=0.05, validation=0.05.
Weights must sum to 1.0 (validated at startup). Validation prior is a neutral 0.5 until M5 results exist.

**Tier assignment:**
- `Immediate` — KEV flag **or** score ≥ 80
- `Accelerated` — score ≥ 50
- `Standard` — otherwise

Retired issue priorities are removed; dependent cases become stale.

---

## 10. Fingerprinting and dedup logic

```
fingerprint = SHA256(cwe_root + "|" + canonical_path + "|" + parameter_class)
```

- `cwe_root`: resolved via `CWE_PARENT_MAP` (e.g. CWE-564→CWE-89, CWE-80→CWE-79)
- `canonical_path`: URL stripped of scheme/host; numeric segments collapsed to `{id}`
- `parameter_class`: `id` / `auth` / `redirect` / `file` / `generic` / `NO_PARAM`

**Hard-block merge rules (both stages):** Different host, asset, package, or parameter class → never merged automatically, even if descriptions are semantically similar.

**Lifecycle guarantees:**
- Canonical IDs derive from sorted finding membership → stable across reruns.
- Reruns publish an atomic snapshot; old issues remain retrievable with `active=false`.
- Analyst merge/split actions are idempotent and persisted; reviewed groups are protected.
- Legacy conflicting groups return HTTP 409 for manual resolution.

---

## 11. Design system

### 11.1 Visual direction

Calm editorial intelligence product, not a dark security console. Generous whitespace, light display type, structured evidence tables, rounded pastel surfaces, restrained warm-black action colour.

### 11.2 Colour tokens

| Token | Value | Use |
|---|---|---|
| `ink` | `#0C0A09` | Headlines, primary text, primary buttons |
| `body` | `#4E4E4E` | Supporting text |
| `muted` | `#777169` | Metadata, timestamps, inactive states |
| `sage` | `#CCD5AE` | Completed stages, low-risk panels |
| `light-sage` | `#E9EDC9` | Secondary cards, neutral success surfaces |
| `ivory` | `#FEFAE0` | Main canvas |
| `cream` | `#FAEDCD` | Warnings, pending work, reproduction context |
| `tan` | `#D4A373` | Strong borders, selected context |
| `white` | `#FFFFFF` | Dense evidence/table surfaces |
| `success` | `#16A34A` | Verified system success only |
| `error` | `#DC2626` | Failures and destructive warnings |

### 11.3 Typography

- **Doto SemiBold** — dotted display face (bundled locally); wordmark, hero headline, section titles, key metrics.
- **Times New Roman / serif fallback** — editorial secondary headings, large risk scores.
- **Inter / Arial / sans-serif** — body copy, controls, navigation, tables.
- **Consolas / monospace** — identifiers, hashes, model versions, endpoints, preserved evidence.

Never use the dotted face for paragraphs, table rows, or API payloads.

### 11.4 Layout and shape

- Content width: 1200px; gutters: 24px desktop / 16px mobile.
- Feature card radius: 16px; evidence panels: 12px; inputs: 8px; buttons/badges: pill (full radius).
- Borders: 1px hairlines. Hover elevation: `0 4px 16px rgba(0,0,0,.04)`.

### 11.5 Navigation

8 sections: Overview · Corpus · Findings · Clusters · Priorities · Validation · Cases · System.

### 11.6 Screen specifications

| Screen | Key information | Actions |
|---|---|---|
| **Overview** | Status strip, real metrics from `/dashboard/metrics`, recent pipeline result | Open filtered feature view |
| **Corpus** | 6–10 fixture cards; scanner, family, count, load state | Load selected / all; show normalized/warning/rejected counts |
| **Findings** | Searchable table: title, scanner, severity, endpoint, completeness | Open detail; extract missing views |
| **Four views** | Description/Location/Reproduction/Impact cards with status and confidence | Extract/re-extract; copy redacted text |
| **Clusters** | Method, status, members, similarity | Compare endpoints; confirm merge or keep-separate |
| **Priorities** | Tier/score queue; 6-contribution bars; threat provenance | Recalculate; filter by tier |
| **Validation** | Issue selector, scenario, allowlisted host, verdict, redacted artefacts + SHA-256 | Simulate; view artefacts; retry inconclusive |
| **Cases** *(planned)* | Pending/approved/rejected queue; tier + stale badge | Approve/reject with actor + reason; request evidence |
| **System** | API health, DB readiness, mock feed mode, model backend | Retry checks; link API docs |

### 11.7 Trust language

Use these terms consistently everywhere in the UI:

| Term | Meaning |
|---|---|
| **Reported** | Supplied by a scanner fixture |
| **Derived** | Normalised, extracted, or calculated by the platform |
| **Inferred** | Rule-based content with stated confidence |
| **Simulated** | Produced by the deterministic offline lab |
| **Reviewed** | Explicitly decided by a human analyst |

Validation verdicts: `simulated_match` · `simulated_no_match` · `inconclusive`. Never use "exploited," "confirmed vulnerability," or visually equivalent success claims.

### 11.8 Definition of done (UI)

1. Uses real API data; handles empty, loading, success, and error states.
2. Desktop, tablet (640–1024px), and mobile (<640px) layouts work.
3. Keyboard navigation, focus management, and dialog behavior verified.
4. No user-controlled HTML rendered unsafely; all API text escaped before DOM insertion.
5. Simulation and mock provenance remain visible.
6. JS syntax check, backend regressions, and browser checks pass.
7. Module spec, current-state section above, and TASK_LOG.md remain aligned.

---

## 12. Roadmap

| Phase | Deliverables | Exit criteria |
|---|---|---|
| **Done — R0** | Reproducible runtime, isolated tests, dedup invariants, truthful provenance | 49 tests pass; pip check; Uvicorn smoke; reruns idempotent |
| **Done — F1** | Synthetic-corpus demo frontend | 6 fixture sets load; pipeline/evidence/risk interactive; simulation labelled |
| **Done — M5** | Lab validation + immutable evidence | 3 scenarios round-trip; hashes verified; Docker rejected; no real target requests |
| **Next — M6** | Case assembly + human review | Assembly/review tests; actor/reason required; audit history; stale guard |
| **M7** | Case review dashboard | Browser checks of queue/detail/review/audit; empty and error states |
| **P9** | Pipeline orchestration + full-corpus demo | All 140 inputs accounted for; no forbidden merges; rerun recovery |
| **P10** | Real Docker, live feeds, Slack/Jira | Separately scoped; do not implement without explicit instruction |

### Next task: M6 (cases and human review)

1. **M6A — Case assembly:** write `docs/MODULE_SPECS/M6_cases_review.md` first; implement `schemas/case.py`, `repositories/case_repo.py`, `services/case_service.py`; assemble active issue + findings + views + priority + validation refs; generate/get/list APIs.
2. **M6B — Human review:** pending → approved/rejected/evidence-requested transitions in one SQLite transaction; actor + non-blank reason required; append-only audit events; reject repeated terminal decisions with 409; never auto-approve.
3. **M7 — Dashboard** depends on stable M6 APIs; do not implement until M6B is complete.

**Deferred until after P9:** real Docker, live threat feeds, Slack, Jira, scanner polling.

---

## 13. Key design decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-09-11 | `pydantic-settings` for config | Automatic type coercion, `.env` reading, validation built-in |
| 2026-09-11 | SQLite WAL + FK constraints | Better concurrent reads; FK enforcement prevents orphaned data |
| 2026-09-11 | `threat_intelligence` uses `cve_id` as PK | CVE ID is the natural key; no surrogate UUID needed |
| 2026-09-11 | Risk weights validated at startup | Fail fast; bad config caught at startup, not mid-request |
| 2026-09-11 | Two-stage dedup (fingerprint + HDBSCAN) | Stage A deterministic; Stage B semantic; both enforce hard blocks |
| 2026-09-11 | SHA-256 token hashing fallback for embeddings | Guarantees vectors without model download; explicitly not semantic |
| 2026-09-11 | Additive SQLite migrations | Preserves existing databases; `CREATE TABLE IF NOT EXISTS` is idempotent |
| 2026-09-12 | Content-addressed mock feed cache | Cache invalidated by file content change, not time; reproducible |
| 2026-09-12 | Canonical IDs from sorted membership | Stable across reruns; prevents phantom duplicate issues |
| 2026-09-12 | Legacy conflicting reviewed groups → 409 | Forces manual reconciliation; no silent data overwrite |
