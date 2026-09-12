# Feature UI/UX and delivery plan

Design authority: [Application design](design.md). This is an implementation-ready design and
sequence, not a claim that the remaining screens or backend features have shipped.

## Constraints and shared design

Preserve the selected sage, light sage, ivory, cream and tan palette; warm ink buttons; rounded
cards; Doto for selected main titles; readable body and evidence typography. Claimcheck is not
bundled: number typography currently falls back to Doto. Use the existing FastAPI, SQLite and
local vanilla frontend. No framework migration, external services or asset downloads are needed.

Use a compact application navigation: Overview, Corpus, Findings, Clusters, Priorities, Validation,
Cases and System. Keep feature views in the existing application, with shared list, filter, detail,
status, notification and confirmation components. Preserve the selected record when switching views.
On phones, use wrapping navigation, stacked detail panels and locally scrolling tables.

Every feature must support empty, loading, populated, partial failure and retry states. Errors must
include the failing operation and a useful retry action. A failed request must not erase unrelated
loaded data. Announce progress through a live region; keep modal close enabled during requests,
restore focus after closing and respect reduced motion. Use text labels alongside semantic colors.

## Feature screen contracts

| Feature | Layout and information | Actions and feedback | Backend and acceptance gate |
|---|---|---|---|
| Overview | Compact status strip, real metrics, recent pipeline result, next incomplete stage | Open a filtered feature view from a metric; refresh without losing selection | Existing metrics plus persisted stage information when added; distinguish history from active counts |
| Synthetic corpus | Six export cards with scanner identity, family, count, load state, source filename and provenance | Load selected/all; show normalized, warning, rejected and already-loaded counts; explain retry | Fixed catalog already exists; repair SARIF parser routing and add idempotent source loading before declaring all 110 records correct |
| Normalized findings | Searchable table with scanner/family/severity filters, quality badge, endpoint and parameter | Open detail even before extraction; show normalization warnings and source provenance; extract missing views | Findings APIs exist; absence of views is a useful empty state, not a failed modal |
| Four views | Description, location, reproduction and impact cards with status, confidence and source fields | Expand text; extract/re-extract with visible result; copy redacted text | Existing extraction APIs; original scanner evidence remains unchanged |
| Embeddings | Detail panel with backend, version, dimension, input hashes and missing views | Generate/retry; explain lexical fallback; disclose skipped semantic stage | Existing embedding APIs; model download is opt-in, incompatible vectors are not compared |
| Pipeline | Four stage cards with live completed/total counts and error details | Run; retry the failed stage; optional explicit validation step after issue creation | Existing stages callable separately; backend orchestrator is a later dependency, not required for initial feature completion |
| Clusters | List with method, status, members and reason; side-by-side member comparison | Compare endpoint/host/parameter/package and views; confirm merge or keep-separate; refresh affected issues | Merge/split APIs exist; surface 409 conflict with explanation; do not invent an unsupported arbitrary regrouping API |
| Priorities | Sortable tier/score queue; detail with six contribution bars, weights, explanations and threat provenance | Recalculate one issue; filter by tier; navigate to source finding or validation | Existing priority API; show mock source, freshness and neutral prior explicitly |
| Validation | Issue selector, supported scenario, normalized allowlisted host, result summary and retained evidence | Explicit simulation; view every artifact, copy hash, retry inconclusive result; open existing run without rerunning | Validate/get/evidence APIs exist; add paginated run history API for a persistent queue; verify bytes before claiming hash integrity |
| Cases | Pending/approved/rejected/evidence-requested queue, tier and stale badge; detail combines all module outputs | Generate/reuse case; request evidence; approve/reject with actor and reason | Requires M6 schemas, repository and assembly service; missing prerequisites shown explicitly |
| Review and audit | Decision form followed by chronological actor/action/reason/time entries | Confirm terminal decisions; explain override with old/new tier; refresh stale snapshots before review | Requires transactional state transitions, append-only audit and concurrency checks; no automatic human approval |
| System | API connectivity, database readiness, mock feed mode, model backend and simulator availability | Retry checks; link API docs; show unsupported capabilities distinctly | One FastAPI process hosts these services; SQLite needs no separate daemon; cases/live feeds/Docker cannot be labelled healthy merely because routes exist |

## Efficient implementation order

Estimates are working ranges for one focused developer, not deadlines. Reuse existing APIs and
components; discover blockers early rather than redesigning everything first.

| Increment | Target effort | Files / scope | Completion evidence |
|---|---|---|---|
| A. Data and service baseline | 30–45 min | Demo loader service/repository, SARIF dispatch, fixture import tests, startup/readiness checks | All six fixtures normalize with meaningful title/CWE/location/severity; 110 accounted for in a fresh DB; repeated load adds no duplicates; existing user DB preserved |
| B. Shared shell and feature views | 45–75 min | Static HTML/CSS/JS, shared state/request/render helpers | Selected design retained; navigation, filters, progress/retry, empty details and keyboard interaction work |
| C. Existing module completion | 45–75 min | Findings/views/embeddings, cluster comparison/actions, risk explanation, validation history | One complete path through every implemented module; errors retain evidence and report actual failed stage |
| D. Case backend and review UX | 75–120 min | M6 spec first, case schemas/repository/service/routes/tests, Cases view | Atomic assembly/review/audit, actor/reason required, stale and concurrent decision guards, no duplicate cases on rerun |
| E. Integrated acceptance and handoff | 30–45 min | Full-corpus test, browser desktop/mobile checks, task log, setup/demo notes | Fresh-corpus workflow, protected nonmerges, evidence integrity, review history and rerun checked; feature branch pushed |

Total estimate: roughly 4–6 hours, with D carrying the most uncertainty. If time tightens, deliver
A–C and acceptance first, and retain D as clearly planned. Do not trade off source preservation,
truthful simulation labels or transactional review behavior to meet a visual deadline.

Avoid repeatedly running all tests after cosmetic edits. Run focused checks per change and the
full suite after integrated milestones. Use a temporary database for fixture and mutation checks.
Do not reset the existing demonstration database to hide incorrect historical imports.

## Core changes and handoffs

New instructions can change layout, terminology, ordering or interaction while work proceeds.
Record the change once, identify affected contracts and revise only the relevant increment. For
schema changes, update producers and consumers together; prefer additive migrations. Clarify only
when a change would delete existing evidence or introduces an unresolved product decision.

If multiple contributors join, assign file ownership before starting. One owner integrates shared
HTML/CSS/JS; one owns backend case contracts; one can verify fixtures and integration in isolated
storage. Avoid simultaneous edits to the global stylesheet, schema migrations and task log.

## Current verification and known gaps

- Local API on `http://127.0.0.1:8001`: health, catalog, metrics, findings, issues, clusters and
  priorities return HTTP 200. Health reports 14 tables, mock feeds and offline simulator mode.
- Current database contains 105 findings, 22 active issues, 22 priorities and zero validations at
  inspection time. This is existing demo state, not a verified fresh 110-record corpus.
- Some issues are titled `Untitled Vulnerability`; demo loading discards the SARIF format hint and
  passes SARIF result objects to flat scanner parsers. Increment A must address this.
- Repeated dataset loads currently append records. UI queries currently stop at 500 rows, and
  pipeline error accounting can mark later successful stages failed after an earlier error.
- Case and review routes return 501 by design; real Docker and live threat feeds remain unsupported.
- Browser automation was unavailable in earlier turns. Rendered verification must be retried during
  acceptance; API checks and syntax checks alone do not establish visual correctness.

All delivery stays on frontend feature branches. `main` is not a publication target for this work.

Planning-turn checks: 57 tests passed (one upstream deprecation warning), `pip check` found no
dependency conflicts, JavaScript syntax passed and `git diff --check` passed. These checks verify
the existing baseline; they do not mark increments A–E complete.
