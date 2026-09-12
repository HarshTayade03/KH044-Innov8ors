# KH044 Innov8ors - AI-Assisted Triage Platform

An advanced, AI-assisted platform designed to streamline vulnerability triage. Security teams today face alert fatigue from hundreds of raw findings across multiple scanners. The **AI-Assisted Triage Platform** automates the heavy lifting by normalizing data, intelligently deduplicating similar issues, validating exploitability in an offline sandbox, and prioritizing threats using risk intelligence—while ensuring analysts retain final review and approval authority.

## 🚀 Key Features

*   **Universal Ingestion & Normalization**: Automatically ingests and normalizes reports from Nessus, Burp Suite, Snyk, Trivy, SARIF, and ZAP into a canonical format.
*   **AI-Powered Deduplication**: Uses semantic embeddings (SentenceTransformer) and HDBSCAN to intelligently cluster duplicate findings across different tools into single, trackable canonical issues.
*   **Offline Sandbox Validation**: Safely simulates common vulnerabilities (SQLi, XSS, SSRF) to gather immutable, cryptographically-hashed evidence of exploitability.
*   **Threat Intel & Risk Prioritization**: Computes a weighted risk score utilizing contextual threat intelligence (like KEV and EPSS data) to bubble up critical threats.
*   **Case Management & Analyst Console**: Generates actionable cases for human review, complete with full audit logs and provenance tracking.

## 🗺️ System Architecture & Module Specs

The system is broken down into distinct, modular phases. For an overall view, check out the [Overall Architecture Diagram](docs/ARCHITECTURE.md).

For detailed specifications and architecture diagrams of each module, see:
*   [M0: Bootstrap & Configuration](docs/MODULE_SPECS/M0_bootstrap.md)
*   [M1: Parsers & Normalizer](docs/MODULE_SPECS/M1_parsers_normalizer.md)
*   [M2: Views & Embeddings](docs/MODULE_SPECS/M2_views_embeddings.md)
*   [M5: Sandbox Validation & Evidence](docs/MODULE_SPECS/M5_sandbox_evidence.md)
*   [M6: Cases & Human Review](docs/MODULE_SPECS/M6_cases_review.md)
*   [F0: Validation Frontend Console](docs/MODULE_SPECS/F0_validation_frontend.md)
*   [F1: Synthetic Demo Dashboard](docs/MODULE_SPECS/F1_synthetic_demo_dashboard.md)
*   [R0: Baseline Reliability](docs/MODULE_SPECS/R0_baseline.md)

## 📖 Developer Documentation

*   [Current modules and features status](docs/CURRENT_STATE.md)
*   [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
*   [Product Reference](docs/ai-assisted-triage_product_reference.md)
*   [Task log and verification history](TASK_LOG.md)
*   [Agent instructions & development guide](docs/agent-instructions.md)

## ⚙️ Setup & Installation

The backend is built with FastAPI and runs on Python 3.12. SQLite is used for lightweight persistence.

```powershell
# 1. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 2. Install dependencies
python -m pip install -r requirements.txt

# 3. Start the application
python -m uvicorn src.app.main:app --reload --port 8000
```

> **Note**: Consult `.env.example` for configuration options. Defaults use local SQLite, mock feeds, and offline sandbox execution.

### Exploring the Platform

Once the server is running, you can access:
*   **Analyst Dashboard**: [http://localhost:8000/](http://localhost:8000/)
*   **Interactive API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
*   **System Health**: [http://localhost:8000/health](http://localhost:8000/health)

## 🧪 Testing

The repository maintains an extensive test suite covering parsing, embedding generation, deduplication lifecycles, and risk scoring.

```powershell
venv/Scripts/python.exe -m pytest tests/ -q
venv/Scripts/python.exe -m pip check
```

*To reproduce the exact environment, use `requirements-lock.txt`.*

## 📂 Repository Structure

| Path | Purpose |
|---|---|
| `src/app/` | Core backend source code (API routes, services, parsers, database schemas) |
| `src/app/static/` | Synthetic corpus dashboard frontend |
| `data/` | Synthetic vulnerability datasets (110 findings) and mock threat intel |
| `tests/` | Comprehensive pytest suite |
| `docs/` | System architecture, module specifications, and developer plans |
