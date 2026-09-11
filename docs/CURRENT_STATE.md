# Current modules and features

Audit: 2026-09-12. Evidence: source files, schemas, routes, fixtures, and tests.
Implemented means code exists, not that it passed runtime checks in this audit.
Python is unavailable here; historical test passes remain historical.

## Module inventory

| Module / phase | Existing implementation | Status and limitations |
|---|---|---|
| M0 / P0 bootstrap | `src/app/main.py`, `config.py`, `database.py`; six routers, health route, SQLite initialization | Implemented; 14 table definitions, not 13. Runtime/dependency compatibility unverified here. |
| M1 / P1 ingestion | `schemas/canonical.py`, `parsers/`, `services/normalizer.py`, `api/ingestion.py`, `repositories/findings_repo.py` | Upload, direct JSON, manual API; CVE/CWE/severity normalization, fingerprinting, quality and provenance. Parser names: nessus, burp, snyk, trivy, sarif, zap. Native export variants need broader tests. |
| D1 / P2 data | Six scanner fixtures, two mock feed files in `data/`; `scratch/generate_datasets.py` | Intended corpus: 110 findings (50 SQLi, 40 XSS, 20 SSRF); count verification recorded in task log. |
| M2 / P3 views and embeddings | `schemas/views.py`, `services/extractor.py`, `services/embedding.py`, `api/findings.py` | Four views, redaction, single/batch operations, weighted similarity. Lazy SentenceTransformer; fallback is pure Python SHA-256 token hashing, not HashingVectorizer. Fallback metadata still uses configured model name. |
| M3 / P4 deduplication | `schemas/dedup.py`, `services/deduplicator.py`, `repositories/dedup_repo.py`, `api/clusters.py` | Fingerprint groups, optional HDBSCAN, canonical issues, merge/split handlers. Correctness gaps below. |
| M4 / P5 prioritization | `schemas/risk.py`, `services/risk_engine.py`, `services/threat_intel.py`, `repositories/risk_repo.py`, priority routes in `api/cases.py` | Mock KEV/EPSS and SQLite cache; weighted score, three tiers, explanations. Live flags unused by enrichment; validation factor fixed at 0.5. |
| M5 / P6 validation | DB tables `validation_runs`, `artifacts`; `schemas/validation.py`, `api/validation.py` | Schema comments and three HTTP 501 routes. No simulator, sandbox service, evidence repository, or Docker executor. |
| M6 / P7 cases | DB tables `cases`, `reviews`, `audit_events`; `schemas/case.py`, case routes | Schema stub and seven HTTP 501 case/review routes. No case assembly, state machine, or append-only audit implementation. |
| M7 / P8 dashboard | `static/index.html`, `api/dashboard.py` | Placeholder page; HTTP 501 metrics. No upload form, queue, review controls, or inspector. |
| P9 integration | No full pipeline orchestrator or end-to-end suite | Not started; current stages require separate API calls. |
| P10 integrations | `workers/scanner_poller.py`; config placeholders | Poller raises NotImplementedError. Slack/Jira/webhook implementations absent. |

Paths in the table are relative to `src/app/` unless already qualified otherwise.

## API surface

Application routes use `/api/v1`; `/`, `/health`, and `/docs` are root routes.

- Ingestion: `POST /findings/upload`, `/findings`, `/findings/manual`.
- Findings: list/detail GET, single/batch view extraction and embedding routes in `api/findings.py`.
- Deduplication: `POST /deduplication/run`, cluster list/detail and merge/split, canonical issue list/detail.
- Priority: `POST /canonical-issues/{canonical_issue_id}/prioritize`, `GET /priorities`,
  `GET /priorities/{canonical_issue_id}`.
- Stubs: validation/evidence, case generation/review, and dashboard metrics.

## Findings that change next steps

1. `stage_a_fingerprint_dedup()` does not call `_check_hard_blocks()`. Equal fingerprints can
   bypass asset/package/parameter protections. Stage B assigns blocked pairs distance 1.0;
   this alone is not a guarantee that a final cluster contains no blocked pairs.
2. Dedup reruns generate new UUIDs. Merge changes cluster status only; split creates singleton
   issues without retiring the previous issue. Define idempotency and downstream consistency before cases.
3. `threat_intel.py` reads cache/mocks only; no live HTTP fetch exists despite earlier completed tasks.
   Cache freshness and source-switch behavior are undefined.
4. Risk scoring hardcodes `val_norm = 0.5` and `sandbox_validated = False`. Explanations do not
   itemize numeric validation and KEV contributions completely.
5. Embedding fallback provenance is inaccurate; semantic clustering is skipped without sklearn.
   Clean installation, offline model behavior, and both dependency paths need verification.
6. There are 21 `test_` functions in five files. No validation, case, dashboard, complete API,
   or 110-finding integration suite exists. `tests/conftest.py` initializes configured DB storage.
7. Only M0-M2 specs exist. Earlier instructions listed nonexistent M3-M7 specs as present.
8. The placeholder UI displays the internal name; correct it during dashboard implementation.

## Done-work interpretation

The old tracker reported 55 completed tasks across P0-P5 and 24 remaining across P6-P9.
This audit reopens three overstated tasks: M3-05, M4-01, and M4-02. That leaves 52 marked
complete in the original 79-task baseline, without fresh runtime verification. The unnamed
bootstrap stub row and P10 tasks are excluded from that historical baseline. Newly added R0
remediation and documentation tasks are tracked separately, rather than inflating old totals.
