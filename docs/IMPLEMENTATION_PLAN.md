# Implementation plan and revised next steps

Updated: 2026-09-12. [Current state](CURRENT_STATE.md) records source evidence;
[TASK_LOG.md](../TASK_LOG.md) records task status and checks.

## Work already done

The backend has bootstrap/configuration/storage, scanner normalization, synthetic data,
four-view extraction, embeddings with a fallback, deduplication, mock-based prioritization,
and offline lab validation with evidence. P0-P7 have implementation; live feeds and Docker remain deferred. P8-P9 remain incomplete.
A registered route or database table is not a completed feature.

## Revised sequence and completion gates

For the selected design's feature-by-feature UX, current service verification, time estimates and
small implementation increments, follow [Feature UI/UX plan](FEATURE_UX_PLAN.md). Its first gate
repairs synthetic SARIF loading and repeat imports before expanding the dashboard and case flows.
Increment A is implemented and verified with 60 tests (Windows WMI test workaround documented in
the feature plan). Next is B: shared navigation and feature views.

| Order | Phase | Deliverables | Exit criteria |
|---|---|---|---|
| Done | R0: reliable baseline | Reproducible runtime, isolated tests, dedup invariants and lifecycle, truthful feed/model provenance | Clean install; current and regression tests pass; health/API smoke checks pass; reruns do not duplicate active issues. |
| Done | F1 demo frontend | Synthetic-corpus console over implemented APIs | Fixed fixture catalog, workflow stages, evidence details, risk and offline validation are interactive; upload/manual inputs removed. |
| Done | P6 / M5: lab validation and evidence | Contracts, local simulator, immutable redacted artifacts, repository/API, risk integration | 55 tests pass; three scenarios round-trip; timeout/unknown inconclusive; allowlist and Docker rejected; hashes verified; no real target requests. |
| Done | P7 / M6: cases and review | Assembly, state transitions, required reasons, audit history, overrides | Case contracts, assembly snapshots, stale rebuilds, review routes and audit history implemented; focused acceptance tests added. |
| 4 | P8 / M7: case review dashboard | Case queue/detail, review controls and audit timeline | Initial queue/detail/actions are wired; browser checks of review flows and loading/empty/error states remain. |
| 5 | P9: integration/demo | Pipeline orchestration, full-corpus test, demo, setup docs/diagram | All 110 inputs accounted for; provenance preserved; no forbidden merges; human review; rerun and partial-failure recovery. |
| Later | P10: external capabilities | Real Docker executor, live feeds, scanner polling/webhooks, Slack/Jira | Separately scoped implementations and controlled integration tests. |

## R0 implementation and acceptance

- **R0-01 Runtime and test isolation:** verify a Python interpreter against existing pins;
  document a clean install; replace shared storage fixtures with temporary databases;
  keep downloads out of deterministic unit tests. Verify startup, health, ingestion and persistence.
- **R0-02 Dedup guarantees (reopens M3-05):** enforce asset/package/parameter blocks in both
  stages and every final cluster. Test equal fingerprints across incompatible findings,
  semantic bridge cases, and valid cross-scanner duplicates.
- **R0-03 Lifecycle consistency:** define one active canonical representation per finding set;
  make rerun/merge/split operations idempotent and transactional. Invalidate/recompute dependent
  priorities/cases when membership changes. Test repeated runs and split/merge sequences.
- **R0-04 Honest provenance:** label hashing fallback and skipped semantic clustering; define
  cache source/freshness policy; explicitly reject unsupported live mode or report mock mode.
  Itemize every risk contribution. Move threat cache SQL into a repository when addressing it.

R0 is complete: 49 tests pass, pip check passes, and actual Uvicorn HTTP smoke checks pass. See
[the R0 contract](MODULE_SPECS/R0_baseline.md) and TASK_LOG.md for results. Live clients remain deferred.
The next phase is P7: case assembly and human review. See `AGENT_HANDOFF.md` for pickup packages.

F1 replaces analyst ingestion controls with a no-build synthetic demonstration dashboard. It
loads the six prepared fixtures, reports stored metrics, exercises P0-P6 and displays simulated
validation evidence. P8 still needs case review and audit features after P7 APIs stabilize.

## P6 implementation contract

Before coding, create `docs/MODULE_SPECS/M5_sandbox_evidence.md` aligned with existing
`validation_runs` and `artifacts` tables. Implement `schemas/validation.py`, `services/sandbox.py`,
`repositories/validation_repo.py`, and existing validation routes under `src/app/`.

- Record issue ID, mode, scenario, timestamps, verdict, limitations, and artifact references.
- Default to deterministic offline SQLi/XSS/SSRF scenarios. Label all results simulated;
  scanner/CWE classification never confirms real exploitability.
- Check configured lab hosts before invoking any executor. Unknown scenarios and timeouts
  are inconclusive; disallowed hosts are rejected. Never execute submitted scanner payloads.
- Preserve raw sources. Redact derived artifacts before persistence/display; SHA-256 hashes
  must cover exactly the retained and served bytes. Runs/artifacts are append-only with new IDs.
- Return 404 for missing issue/run IDs and typed results for validation/evidence APIs.
- Integrate validation into risk scoring with explicit rules for simulation and inconclusive results.
- Add `tests/test_validation.py` for three scenarios, unsupported input, timeout, allowlist,
  redaction, hash integrity, persistence, retrieval, repeated runs and risk integration.
- Defer real Docker execution (M5-03). Unsupported enabled mode must fail explicitly. Complete
  the six lab/evidence tasks before calling P6 complete; retain the Docker deferral visibly.

## Subsequent contracts

P7 assembles canonical issue, findings, views, priority, validation and artifact references.
Require reasons for approval/rejection/overrides; audit each change in the same transaction.
Define pending/approved/rejected transitions and evidence-request behavior in the M6 spec first.

P8 implements the seven existing F1 tasks against stable P7 APIs using the public product name.
Do not display placeholder metrics as measured data. P9 reports per-stage progress, retries
partial failures safely, and demonstrates accepted duplicates and protected nonmerges.

## Execution history

The first request required documentation repair, so that turn produced the audit and roadmap.
The follow-up "continue" authorized R0 implementation. This phase establishes a tested baseline;
R0 acceptance passed; P6 is the next application phase.


## Shared execution checkpoint (2026-09-12)

A is verified. B feature shell/details is implemented with five frontend behavior checks;
rendered acceptance remains pending. Copilot owns P7, whose four current focused tests pass;
the combined Python suite has 64 passing tests (Windows architecture workaround).
Continue C with cluster comparison/review and validation history, then complete D inline case
review/audit UX against Copilot's contract. Finish E with desktop/mobile and full-flow acceptance.
Current combined runtime: http://127.0.0.1:8002. All delivery remains off main.


### C/D frontend checkpoint (2026-09-12)

Cluster comparison and guarded merge/split controls, complete selected-issue validation history,
and inline case decisions/overrides/regeneration/review/audit views are implemented. Source files:
module-review.js and case-review.js. Copilot owns the evolving backend. Eleven frontend behavior
checks pass; the combined backend snapshot passed 68 tests with the Windows test workaround.
The runtime on port 8002 serves the current history contract. Full desktop/mobile/keyboard and
fresh-corpus interactive acceptance remain next. Preserve concurrent edits and never push main.
