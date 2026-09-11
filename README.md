# KH044 Innov8ors - AI-Assisted Vulnerability Triage Platform

A prototype that normalizes security scanner findings, extracts four structured views,
deduplicates findings, and assigns explainable risk priorities using mock threat intelligence.

**Current status (2026-09-12):** backend phases 0-5 have implementation with known correctness
and verification gaps. Sandbox validation, cases/human review, dashboard metrics, and the full
pipeline are not implemented. The home page is a placeholder. Live KEV/EPSS fetching is absent.

## Start here

- [Current modules and features](docs/CURRENT_STATE.md)
- [Done work and revised implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Task log and verification history](TASK_LOG.md)
- [Agent instructions](AGENTS.md) and [development guide](docs/agent-instructions.md)

## Setup

From the repository root, with a Python interpreter compatible with requirements.txt:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn src.app.main:app --reload --port 8000
```

Consult .env.example for configuration. Defaults use local SQLite, mock feeds, and disabled
real sandbox execution. The pinned dependency set and historical Python 3.14 setup need clean-install
verification (R0-01); this audit machine has no installed Python interpreter.

Open [API docs](http://localhost:8000/docs), [health](http://localhost:8000/health), or the
[placeholder home page](http://localhost:8000/). npm start only runs legacy JavaScript scaffolding.

## Tests

Use disposable storage because the current fixture initializes the configured database:

```powershell
$env:DATABASE_PATH = Join-Path $env:TEMP ('triage-tests-' + [guid]::NewGuid() + '.db')
python -m pytest tests/ -q
```

There are 21 test functions across parser, normalizer, extractor, deduplication and risk tests.
They were not runnable in the 2026-09-12 audit; see TASK_LOG.md for the limitation.

## Repository layout

| Path | Purpose |
|---|---|
| src/app/main.py, config.py, database.py | FastAPI entrypoint, settings, SQLite with 14 table definitions |
| src/app/parsers/ and schemas/ | Scanner adapters and pipeline contracts; validation/case schemas are stubs |
| src/app/services/ and repositories/ | Normalization, views, embeddings, deduplication and mock risk enrichment |
| src/app/api/ | Backend routes, including explicit HTTP 501 placeholders |
| src/app/static/index.html | Placeholder for the future analyst dashboard |
| data/ | 110 synthetic findings and mock KEV/EPSS feeds |
| tests/ | Existing backend tests |
| docs/ | Current status, roadmap, requirements and M0-M2 specs |

Adapters exist for Nessus, Burp, Snyk, Trivy, generic SARIF and ZAP. Bundled findings use
Burp/Nessus/ZAP JSON or SARIF: 50 SQLi, 40 XSS and 20 SSRF. Manual entry is an API capability;
the web form remains planned.

Embeddings use SentenceTransformer when available and pure Python token hashing otherwise.
Semantic clustering uses optional sklearn HDBSCAN. See the module inventory for merge safety,
repeat-run, fallback provenance and risk-validation gaps before relying on results.
