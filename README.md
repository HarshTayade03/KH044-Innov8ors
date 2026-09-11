# KH044 Innov8ors - AI-Assisted Vulnerability Triage Platform

A prototype that normalizes security scanner findings, extracts four structured views,
deduplicates findings, and assigns explainable risk priorities using mock threat intelligence.

**Current status (2026-09-12):** backend phases 0-5 have implementation; R0 adds deduplication safety,
repeatable lifecycle operations, isolated tests and explicit provenance. Offline lab validation and dashboard metrics are implemented;
cases/human review and the full pipeline orchestrator remain planned. The frontend demonstrates the prepared synthetic corpus. Live KEV/EPSS fetching is absent.

## Start here

- [Current modules and features](docs/CURRENT_STATE.md)
- [Done work and revised implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Task log and verification history](TASK_LOG.md)
- [Agent instructions](AGENTS.md) and [development guide](docs/agent-instructions.md)

## Setup

From the repository root, using Python 3.12:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn src.app.main:app --reload --port 8000
```

Consult .env.example for configuration. Defaults use local SQLite, mock feeds, and disabled
real sandbox execution. R0 located a bundled Python 3.12.14 runtime and created a local venv. Use
venv/Scripts/python.exe directly if Python is not on PATH. Model downloads default to disabled
(MODEL_ALLOW_DOWNLOAD=false); a missing cached model uses the explicitly labeled hashing fallback.

Open the [synthetic corpus dashboard](http://localhost:8000/), [API docs](http://localhost:8000/docs),
or [health endpoint](http://localhost:8000/health). The dashboard can load prepared fixtures, run the
implemented core stages, inspect extracted views and embeddings, review clusters, and calculate
mock-feed risk scores. npm start only runs legacy JavaScript scaffolding.

## Tests

Each test uses temporary SQLite storage and a deterministic embedder; external sockets are blocked (local asyncio IPC is permitted).

```powershell
venv/Scripts/python.exe -m pytest tests/ -q
venv/Scripts/python.exe -m pip check
```

Tests cover parsers, views, dedup safety/lifecycle, concurrency/rollback, database migration,
provenance, risk scoring, and API startup/ingestion. **R0: 49 tests passed; pip check and
actual Uvicorn HTTP smoke checks passed.** See TASK_LOG.md for details.

requirements-lock.txt captures the tested transitive versions for Python 3.12 on Windows x64.
Use python -m pip install -r requirements-lock.txt to reproduce that resolved environment.

## Repository layout

| Path | Purpose |
|---|---|
| src/app/main.py, config.py, database.py | FastAPI entrypoint, settings, SQLite with 14 table definitions |
| src/app/parsers/ and schemas/ | Scanner adapters and pipeline contracts; validation/case schemas are stubs |
| src/app/services/ and repositories/ | Normalization, views, embeddings, deduplication and mock risk enrichment |
| src/app/api/ | Backend routes, including explicit HTTP 501 placeholders |
| src/app/static/ | No-build synthetic corpus dashboard for implemented backend APIs |
| data/ | 110 synthetic findings and mock KEV/EPSS feeds |
| tests/ | Existing backend tests |
| docs/ | Current status, roadmap, requirements and M0-M2/R0 specs |

Adapters exist for Nessus, Burp, Snyk, Trivy, generic SARIF and ZAP. Bundled findings use
Burp/Nessus/ZAP JSON or SARIF: 50 SQLi, 40 XSS and 20 SSRF. Manual entry is an API capability;
the web form remains planned.

Embeddings use SentenceTransformer when available and pure Python token hashing otherwise.
Semantic clustering uses optional sklearn HDBSCAN. Dedup summaries expose skipped/failed clustering and the actual embedding backend.
The next phase is lab validation and evidence; current scores explicitly label validation as not attempted.
