# Shared implementation ownership

Current split: Codex owns phase B frontend navigation and details; existing uncommitted M6 changes
are treated as Copilot/user-owned. This file is a shared handoff, not a message sent to Copilot.

- Codex: `src/app/static/workspace.js`, `workspace.css`, script/style wiring in `index.html`,
  frontend checks and this handoff. Existing module APIs remain unchanged.
- Copilot/user: `schemas/case.py`, `repositories/case_repo.py`, `services/case_service.py`,
  `api/cases.py`, `tests/test_cases.py`, and `MODULE_SPECS/M6_cases_review.md`.
- Preserve the user's local `docs/design.md` edit. Stage explicit owned paths only.
- Backend acceptance: case create/list/detail, actor and nonblank reason, stale-case guard,
  transactional review and audit, repeated/concurrent decisions, and priority override semantics.
- Integration gate: publish final M6 request/response contracts and test outcome here or in the M6
  spec. Frontend review controls should be connected only once those contracts are stable.
- Do not change branch or restart shared backend during another contributor's test run without
  coordinating. Never push to main for this task.


## Integration checkpoint

Copilot also added case queue markup/styles and dashboard handlers. Codex preserved these,
added the missing generateAllCases handler, and connected cases to the paginated shared refresh.
The new two-script startup test protects against missing global handlers and refresh conflicts.
64 backend tests (including all four current P7 tests) and five frontend tests pass. Run Python
with the documented platform.machine AMD64 workaround and a distinct --basetemp.
The combined source runs on port 8002; port 8001 still exposes old P7 stubs and was not restarted.
No connected browser is available. Shared worktree changes have not been committed or pushed.

P7 follow-up: add explicit concurrent assembly/terminal-decision and stale-case tests; verify
assembly and audit atomicity and priority-override lifecycle semantics. Existing four tests do
not establish those acceptance claims. Frontend follow-up: inline review forms, audit timeline,
priority override, requested-evidence recovery, cluster review and complete validation history.


### C/D frontend checkpoint (2026-09-12)

Cluster comparison and guarded merge/split controls, complete selected-issue validation history,
and inline case decisions/overrides/regeneration/review/audit views are implemented. Source files:
module-review.js and case-review.js. Copilot owns the evolving backend. Eleven frontend behavior
checks pass; the combined backend snapshot passed 68 tests with the Windows test workaround.
The runtime on port 8002 serves the current history contract. Full desktop/mobile/keyboard and
fresh-corpus interactive acceptance remain next. Preserve concurrent edits and never push main.
