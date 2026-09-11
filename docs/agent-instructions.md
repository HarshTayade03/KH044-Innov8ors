# Development guide

Updated: 2026-09-12. Applies with the root [AGENTS.md](../AGENTS.md).

## Read first

Read [TASK_LOG.md](../TASK_LOG.md), [CURRENT_STATE.md](CURRENT_STATE.md), and
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). Read relevant existing MODULE_SPECS files;
only M0, M1, and M2 currently exist. project_f1.md, vulntriager_product_reference.md, and normal.txt
are read-only requirements/reference material. agent1.md is historical planning context.
Use repository-relative paths, not a previous developer's machine location.

## Architecture

Public name: **AI-Assisted Vulnerability Triage Platform**. Internal name: VulnTriager.
Python/FastAPI and Pydantic v2 provide the backend; SQLite stores pipeline state.
The intended frontend is single-file HTML/CSS/JS without a build step; currently it is a placeholder.
package.json and src/project-source-code/index.js are legacy scaffolding, not the backend launcher.

Actual module paths/status are maintained in CURRENT_STATE.md. Configuration uses pydantic-settings
in src/app/config.py. src/app/database.py defines 14 tables. Routers register in src/app/main.py
under /api/v1. Persistence uses findings_repo.py, dedup_repo.py, and risk_repo.py.
Threat intelligence currently accesses SQLite directly; moving this into a repository is debt.
New modules should use repositories rather than extending this exception.

## Working rules

- Read files before editing. State a short plan for nontrivial work.
- Use feature/<task-id>-<description> branches; never commit directly to main/master.
- Track work in root TASK_LOG.md, not an external artifact directory or nonexistent task.md.
- Mark tasks [/] when started, [x] only after acceptance checks, and [!] when blocked.
- Make small commits using [task-id] docs|feat|fix|test: description.
- If work exceeds 30 minutes, state that and split it into reviewable increments.
- Preserve schema contracts or update every consumer and document the change.
- Keep original scanner evidence immutable. Store redacted derived artifacts separately and hash
  the exact retained/served bytes.
- Separate reported, inferred, simulated, and actually validated information. Scanner claims or
  CWE-based simulation must never automatically confirm real exploitability.
- Keep sandbox execution disabled by default and restricted to configured controlled lab targets.
- Only analyst actions may approve/reject cases. Record actor, reason, and audit events.
- Never edit secrets or .env without explicit authorization, or commit credentials.
- Preserve dependency pins unless changing them is in scope; document dependency changes here.

## Runtime and verification

Run from the repository root:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn src.app.main:app --reload --port 8000
```

Use .env.example as configuration reference. Defaults use mock threat feeds and disable real
sandbox execution. Neither lab simulation nor live threat fetching is implemented yet.
The historical Python 3.14 claim is not a verified compatibility guarantee for existing pins.
Establish a supported interpreter and clean installation in R0-01 before changing dependencies.

Tests currently initialize configured database storage without isolation. Use a disposable path:

```powershell
$env:DATABASE_PATH = Join-Path $env:TEMP ('triage-tests-' + [guid]::NewGuid() + '.db')
$env:KEV_LIVE = 'false'
$env:EPSS_LIVE = 'false'
python -m pytest tests/ -q
```

Run focused tests for code changes and startup/API checks for wiring changes. For documentation,
verify links, paths, counts, and git diff --check. Never claim historical passes as fresh results.
The 2026-09-12 audit could not run Python tests: python was absent and py found no interpreter.

## Scope

Complete a reliable local prototype before live integrations. Slack, Jira, polling/webhooks,
live feeds, and real Docker execution remain deferred in the revised plan. Only the polling
stub exists; notifier and Jira service files do not exist. Simulation must be visibly labeled.
