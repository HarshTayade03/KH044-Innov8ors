# Current modules and features

Audit: 2026-09-12. Evidence: source files, schemas, routes, fixtures, and tests.
Implemented means code exists, not that it passed runtime checks in this audit.
R0 found bundled Python 3.12.14 outside PATH and created a local venv. All 49 tests, pip check and actual Uvicorn smoke checks passed; results
are recorded in TASK_LOG.md; historical pass claims are kept separately.

## Module inventory

| Module / phase | Existing implementation | Status and limitations |
|---|---|---|
| M0 / P0 bootstrap | `src/app/main.py`, `config.py`, `database.py`; six routers, health route, SQLite initialization | Implemented; 14 table definitions, not 13. Additive active-issue/case-stale/cache-source migrations preserve existing databases. |
| M1 / P1 ingestion | `schemas/canonical.py`, `parsers/`, `services/normalizer.py`, `api/ingestion.py`, `repositories/findings_repo.py` | Upload, direct JSON, manual API; CVE/CWE/severity normalization, fingerprinting, quality and provenance. Parser names: nessus, burp, snyk, trivy, sarif, zap. Native export variants need broader tests. |
| D1 / P2 data | Six scanner fixtures, two mock feed files in `data/`; `scratch/generate_datasets.py` | Intended corpus: 110 findings (50 SQLi, 40 XSS, 20 SSRF); count verification recorded in task log. |
| M2 / P3 views and embeddings | `schemas/views.py`, `services/extractor.py`, `services/embedding.py`, `api/findings.py` | Four views, redaction, single/batch operations, weighted similarity. Lazy SentenceTransformer; fallback is pure Python SHA-256 token hashing, not HashingVectorizer. Backend/version and input text hashes are persisted accurately; downloads are opt-in. |
| M3 / P4 deduplication | `schemas/dedup.py`, `services/deduplicator.py`, `repositories/dedup_repo.py`, `api/clusters.py` | Fingerprint groups, optional HDBSCAN, canonical issues, merge/split handlers. Pairwise hard blocks in both stages; stable IDs, atomic active snapshots and repeatable analyst merge/split actions. |
| M4 / P5 prioritization | `schemas/risk.py`, `services/risk_engine.py`, `services/threat_intel.py`, `repositories/risk_repo.py`, priority routes in `api/cases.py` | Mock KEV/EPSS and SQLite cache; weighted score, three tiers, explanations. Unsupported live flags return 503; content hashes refresh mock cache; all contributions and neutral validation prior are explicit. |
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

## R0 changes and remaining limits

- Both stages and final clusters enforce asset/host/package/parameter constraints. Unknown fields
  cannot bridge incompatible members; parameter/package spelling is treated conservatively.
- Nessus parsing now preserves supplied URL, path and parameter context for cross-scanner matching.
- IDs derive from sorted finding membership. Automatic reruns publish an atomic active snapshot;
  historical issues remain retrievable with active=false. Lists/priorities use active issues only.
- Analyst splits reserve singleton members; confirmed merges remain fixed across reruns. A later
  explicit merge can reverse a split if compatible. New reports do not silently alter reviewed groups.
- Retired issue priorities are removed; dependent cases become stale while human decisions,
  validation records and evidence remain intact. P7 must consume the stale flag before reviews.
- Legacy duplicate issues are reconciled on the next run. Overlapping or unsafe reviewed legacy
  groups return 409 for manual reconciliation instead of silently overwriting decisions.
- Mock feeds are the only implemented threat source. Content changes refresh cache entries;
  missing/malformed feeds and live flags fail explicitly. Risk still uses a labeled neutral 0.5
  validation prior until P6. Reprioritize explicitly after changing feeds.
- Hashing vectors are lexical fallback, not learned semantic evidence. Backend/version and input
  text hashes are retained; absent views remove stale vectors. Semantic-stage status is reported.
- Dedup holds a serialized SQLite transaction while computing a snapshot; this favors prototype
  consistency over large-scale concurrent throughput. Cluster lists include historical clusters.
- Cached learned models may be used; R0 tests use offline hashing and real sklearn HDBSCAN.
  Learned-model accuracy is not established by these regression tests.
- Validation, human case review, dashboard and full pipeline remain unimplemented. The placeholder
  UI still displays the internal name; fix it in P8. Only M0-M2 and R0 specs exist.

## Done-work interpretation

The initial audit reopened M3-05 and two live-feed tasks. R0 completes M3-05 and four
additional reliability tasks, with 49 passing tests and recorded acceptance results. Live fetching and Docker
remain deferred. Preserve the original baseline separately from newly added R0 work in TASK_LOG.md.
