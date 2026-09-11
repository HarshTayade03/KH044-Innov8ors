# Multi-agent implementation handoff

Updated: 2026-09-12. Source status is in [CURRENT_STATE.md](CURRENT_STATE.md); this file defines
work packages that can be picked up independently after M5. Agents must read root `AGENTS.md`, the
relevant module spec, and `TASK_LOG.md`, then mark only their assigned rows in progress.

## Verified foundation

M0 bootstrap/storage, M1 ingestion, D1 fixtures, M2 four-view extraction/embeddings, M3 dedup and
lifecycle, M4 mock-feed risk scoring, R0 reliability, and F0 validation UI are implemented. The
baseline before M5 is 49 passing tests plus browser smoke coverage. Live feeds, real Docker,
cases/reviews, dedicated metrics, orchestration and external integrations are absent.

## Critical path and pickup packages

1. **M6A case assembly (depends on M5):** create `M6_cases_review.md`, finish case schemas,
   `case_repo.py` and `case_service.py`. Assemble an active issue with source findings, views,
   priority, latest validation and artifact references. Reuse a non-stale pending case; mark old
   membership cases stale. Deliver generate/get/list APIs and missing/stale tests.
2. **M6B human review (depends on M6A):** implement pending to approved/rejected/evidence-requested
   transitions in one SQLite transaction. Require actor and nonblank reason for every decision and
   override. Append audit events; reject repeated terminal decisions with 409. Never auto-approve.
3. **M7 dashboard completion (depends on M6 APIs; frontend files only after API contract freezes):**
   metrics from stored rows, case queue/detail, validation button/evidence, review controls and audit
   timeline. Preserve simulation/mock labels and loading/empty/error states. Extend browser checks.
4. **P9 orchestration (can start after M5, integrate M6 later):** one idempotent pipeline service
   that ingests, extracts, embeds, deduplicates, prioritizes, optionally simulates and generates
   cases. Return per-stage counts/status/errors and allow safe retry after partial failure.
5. **P9 corpus/demo (independent once orchestration contract exists):** exercise all six fixture
   files (110 source records), assert accounting and protected nonmerges, then write three short demo
   scripts and update architecture/setup docs.

Do not assign real Docker, live feeds, Slack/Jira, polling or webhooks during the five-hour critical
path. They do not unlock the local end-to-end demonstration.
