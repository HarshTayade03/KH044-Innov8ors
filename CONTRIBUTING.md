# Contributing to the AI-Assisted Vulnerability Triage Platform

Thank you for contributing. This guide covers everything you need to set up the project locally, follow team conventions, and get your changes reviewed quickly.

---

## Table of contents

1. [Before you start](#before-you-start)
2. [Local development setup](#local-development-setup)
3. [Project structure](#project-structure)
4. [Branch naming](#branch-naming)
5. [Commit format](#commit-format)
6. [Making changes](#making-changes)
7. [Running tests](#running-tests)
8. [Coding standards](#coding-standards)
9. [Data files](#data-files)
10. [Opening a pull request](#opening-a-pull-request)
11. [Security and ethics rules](#security-and-ethics-rules)

---

## Before you start

Read these documents in order before writing any code:

- [`AGENTS.md`](AGENTS.md) — repository-wide agent and contributor instructions
- [`docs/agent-instructions.md`](docs/agent-instructions.md) — development guide and runtime setup
- [`docs/CURRENT_STATE.md`](docs/CURRENT_STATE.md) — what is implemented vs. planned
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — current roadmap and acceptance criteria
- [`TASK_LOG.md`](TASK_LOG.md) — task status and completion history

If a relevant module spec exists under `docs/MODULE_SPECS/`, read it before editing that module.

---

## Local development setup

**Requirements:** Python 3.12, Git.

```bash
# 1. Clone the repository
git clone https://github.com/HarshTayade03/KH044-Innov8ors.git
cd KH044-Innov8ors

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\Activate.ps1       # Windows PowerShell

# 3. Install dependencies (do not change pinned versions without a specific reason)
pip install -r requirements.txt
pip check                          # must report no broken requirements

# 4. Copy the example environment file and adjust if needed
cp .env.example .env

# 5. Start the development server
python -m uvicorn src.app.main:app --reload --port 8000
```

The API is now available at `http://localhost:8000`. Interactive docs are at `http://localhost:8000/docs`.

---

## Project structure

```
KH044-Innov8ors/
├── data/               # Scanner fixture files and threat-intel mocks
│   └── README.md       # Corpus inventory and format notes
├── docs/               # Architecture, plans, and module specs
│   └── MODULE_SPECS/   # Per-module contracts and acceptance criteria
├── scratch/            # One-off scripts (not part of the production app)
├── src/app/
│   ├── api/            # FastAPI routers — one file per feature area
│   ├── parsers/        # Scanner-specific input parsers
│   ├── repositories/   # All SQLite persistence logic
│   ├── schemas/        # Pydantic v2 models — the contract layer
│   ├── services/       # Business logic — no direct DB access
│   ├── static/         # Single-file frontend (HTML/CSS/JS)
│   └── workers/        # Background task stubs
├── tests/              # pytest test suite
├── AGENTS.md           # Repository-level contributor rules
├── TASK_LOG.md         # Canonical task tracker
└── requirements.txt    # Pinned direct dependencies
```

Key architecture rules:
- **Schemas are contracts.** Change them only when you update every consumer.
- **Services contain business logic.** They call repositories; they do not touch the DB directly.
- **Repositories own persistence.** They use `database.transaction()` for multi-table writes.
- **Parsers are stateless.** They translate one raw record; normalizer builds the final schema.

---

## Branch naming

Always work on a feature branch. Never commit directly to `main` or `master`.

```
feature/<task-id>-<short-description>
fix/<task-id>-<short-description>
docs/<task-id>-<short-description>
```

Examples:
```
feature/M6-01-case-schema
fix/R0-03-dedup-lifecycle
docs/D1-16-edge-case-data
```

The `<task-id>` must match an entry in [`TASK_LOG.md`](TASK_LOG.md). Add one if your work is genuinely new.

---

## Commit format

Use this format for every commit:

```
[task-id] type: short imperative summary (≤ 72 chars)

Optional body explaining WHY (not just what the diff shows).
Include relevant context, design decisions, and known limitations.
```

Types: `feat`, `fix`, `docs`, `data`, `test`, `refactor`, `style`, `chore`.

Examples:
```
[M1-05] feat: implement NessusParser with plugin_name CWE inference
[D1-16] data: add normalization edge-case fixtures for parser stress testing
[R0-02] fix: enforce hard-block merge rules in both dedup stages
[DOC-03] docs: redesign implementation plan with P6–P9 acceptance gates
```

---

## Making changes

1. Mark your task as `[/]` (in progress) in `TASK_LOG.md` at the start.
2. Read any existing code in the module before editing.
3. Keep changes focused. One logical concern per commit.
4. Run the test suite before opening a PR (see below).
5. Mark your task as `[x]` in `TASK_LOG.md` only after tests pass.
6. If you get blocked, mark as `[!]` and describe the blocker in the log.

If your work will take more than 30 minutes, split it into reviewable increments and open a draft PR early.

---

## Running tests

```bash
# Run the full test suite
python -m pytest tests/ -q

# Run a single test file
python -m pytest tests/test_parsers.py -v

# Check dependency integrity after any pip install
pip check
```

All tests must pass before you open a PR. The CI pipeline runs `pytest tests/ -q` and `pip check` on every push.

---

## Coding standards

- **Python 3.12.** Use type hints on all function signatures.
- **Pydantic v2** for all data models. Use `model_validator` and `field_validator` over manual checks.
- **FastAPI conventions:** one router file per feature area; use `APIRouter` with a prefix.
- **No raw SQL in services.** SQL lives in repository files only.
- **No external calls in unit tests.** The network fixture blocks all external sockets; loopback is allowed.
- **No secrets in code.** All secrets come from environment variables via `config.py`.
- **Immutable evidence.** Original scanner data is never modified. Derived artefacts are stored separately.
- **Docstrings on public functions.** Use Google or NumPy style.
- Format code with `black` and lint with `ruff` if you have them installed. Not required, but appreciated.

---

## Data files

Scanner fixture files live in [`data/`](data/). See [`data/README.md`](data/README.md) for the corpus inventory and format documentation.

If you add a new fixture:
- Name it `<scanner>_<vuln_type>.json` or `<scanner>_<purpose>.json`.
- Update `data/README.md` to include it in the corpus table.
- Add a row to `TASK_LOG.md` in the Phase 2 (Synthetic Data) section.
- If the fixture exercises a new edge case, note the expected normalizer outcome in a `_comment` field.

Do not commit credentials, real IP addresses of live production systems, or real personal data to `data/`.

---

## Opening a pull request

1. Push your branch to origin:
   ```bash
   git push -u origin feature/<task-id>-<description>
   ```
2. Open a PR against `main`. Fill in the PR template.
3. Ensure all CI checks pass.
4. Request a review from at least one other team member.
5. Squash or rebase before merging if the branch has many WIP commits.

---

## Security and ethics rules

These rules are non-negotiable and come from [`AGENTS.md`](AGENTS.md):

- **Never commit credentials, API keys, or tokens.** Use `.env` (which is gitignored).
- **Keep sandbox execution disabled by default.** `SANDBOX_ENABLED=false` is the required default.
- **Scanner output is evidence, not confirmed exploitation.** Label all automated conclusions as simulated or inferred; never claim confirmed exploitability without validated sandbox results.
- **Human analysts retain final approval authority.** No automated action may approve or reject a case.
- **Preserve original evidence immutably.** Derived artefacts are stored separately with SHA-256 hashes.
- **Sandbox targets must be explicitly allowlisted.** Never send requests to targets that are not in the configured lab allowlist.

If you identify a real security vulnerability in this project, report it privately to the maintainers rather than opening a public issue.
