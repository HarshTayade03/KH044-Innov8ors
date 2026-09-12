# Development guide

Updated: 2026-09-12. Applies with the root [AGENTS.md](../AGENTS.md).

## Read first

Read [TASK_LOG.md](../TASK_LOG.md), [CURRENT_STATE.md](CURRENT_STATE.md), and
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). Read relevant existing MODULE_SPECS files;
M0, M1, M2 and R0_baseline currently exist. R0_baseline defines the current dedup/lifecycle contract. project_f1.md, ai-assisted-triage_product_reference.md, and normal.txt
are read-only requirements/reference material. agent1.md is historical planning context.
Use repository-relative paths, not a previous developer's machine location.

## Architecture

Public name: **AI-Assisted Vulnerability Triage Platform**. Internal name: AI-Assisted Triage.
Python/FastAPI and Pydantic v2 provide the backend; SQLite stores pipeline state.
The intended frontend is single-file HTML/CSS/JS without a build step; currently it is a placeholder.
package.json and src/project-source-code/index.js are legacy scaffolding, not the backend launcher.

Actual module paths/status are maintained in CURRENT_STATE.md. Configuration uses pydantic-settings
in src/app/config.py. src/app/database.py defines 14 tables. Routers register in src/app/main.py
under /api/v1. Persistence uses findings_repo.py, dedup_repo.py, and risk_repo.py.
Threat intelligence uses threat_intel_repo.py. Multi-repository writes use database.transaction()
so retirement, priority invalidation, case staleness and audit events commit or roll back together.

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
Use Python 3.12 with the existing direct dependency pins. A bundled 3.12.14 runtime was
found outside PATH during R0 and used to create the ignored repository-local venv.
The earlier statement that no interpreter was installed described PATH/py discovery only.
All 12 direct pins installed unchanged and pip check passed. requirements-lock.txt records
the tested transitive versions for Python 3.12/Windows x64; use it to reproduce this environment.
Do not change direct pins without a specific compatibility reason.

Tests now create one temporary SQLite database per test, replace the model with deterministic
hashing, and block external socket connections (literal loopback is allowed for Windows asyncio IPC). Run:

```powershell
venv/Scripts/python.exe -m pytest tests/ -q
venv/Scripts/python.exe -m pip check
```

Run focused regressions for code changes and startup/API checks for wiring changes. Record
actual outcomes in TASK_LOG.md. Mock feed content hashes define cache freshness; live flags
return explicit unsupported-mode errors. MODEL_ALLOW_DOWNLOAD defaults to false; cached
SentenceTransformer models are used when present, otherwise the backend is labeled hashing.
Do not compare embeddings with different backend/version/dimension provenance.

## Scope

Complete a reliable local prototype before live integrations. Slack, Jira, polling/webhooks,
live feeds, and real Docker execution remain deferred in the revised plan. Only the polling
stub exists; notifier and Jira service files do not exist. Simulation must be visibly labeled.
