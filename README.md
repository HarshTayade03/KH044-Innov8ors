# KH044 Innov8ors — AI-Assisted Vulnerability Triage Platform

An automated vulnerability triage system that normalizes findings from multiple security scanners, deduplicates via AI semantic clustering, validates exploitability in a controlled sandbox, and generates analyst-ready cases with transparent risk scoring.

---

## The Problem

Security teams receive hundreds of disorganized alerts from Burp Suite, Nessus, OWASP ZAP, and similar tools — all in different formats, with inconsistent naming, duplicated findings, and unverified severity. Analysts spend hours manually triaging instead of fixing vulnerabilities.

## The Solution

A 9-stage pipeline that:
1. **Normalizes** findings from 5+ scanner formats (SARIF 2.1.0, JSON) into a single canonical schema
2. **Extracts** 4 structured views per finding (Description, Location, Reproduction, Impact)
3. **Deduplicates** using deterministic fingerprinting + AI semantic clustering (HDBSCAN)
4. **Validates** exploitability in a safe lab sandbox simulation
5. **Scores** risk transparently using CISA KEV + EPSS + CVSS + asset criticality
6. **Generates** analyst-ready cases for human review and approval

---

## Quick Setup

```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / Mac

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
copy .env.example .env
# Edit .env if needed (defaults work for prototype)

# 4. Run the server
python -m uvicorn src.app.main:app --reload --port 8000

# 5. Open in browser
# Dashboard:  http://localhost:8000/
# API Docs:   http://localhost:8000/docs
# Health:     http://localhost:8000/health
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Project Structure

```
innov8ors/
├── src/app/
│   ├── main.py              # FastAPI entrypoint
│   ├── config.py            # Environment configuration
│   ├── database.py          # SQLite with 13 tables
│   ├── schemas/             # Pydantic data models
│   ├── parsers/             # Scanner-specific adapters (Nessus, Burp, ZAP, SARIF)
│   ├── services/            # Business logic (normalizer, extractor, deduplicator, etc.)
│   ├── repositories/        # All database access (single repo pattern)
│   ├── api/                 # REST API route handlers
│   └── static/              # Analyst dashboard (single index.html)
├── data/                    # Synthetic scanner data (110 findings: 50 SQLi, 40 XSS, 20 SSRF)
├── tests/                   # Test suite
├── docs/
│   ├── agent-instructions.md    # Cross-agent development guide (read first!)
│   ├── MODULE_SPECS/            # Detailed per-module implementation specs
│   └── project_f1.md            # Hackathon problem statement
├── requirements.txt
└── .env.example
```

---

## Data Formats Supported

| Scanner | Format | Findings in Dataset |
|---|---|---|
| Burp Suite | SARIF 2.1.0 | 25 SQLi + 20 XSS + 10 SSRF |
| Nessus | JSON | 25 SQLi + 10 SSRF |
| OWASP ZAP | JSON | 20 XSS |
| Manual Entry | Web Form / JSON | — |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.14 + FastAPI + Pydantic v2 |
| Database | SQLite |
| Embeddings | `sentence-transformers` (all-MiniLM-L6-v2, 384-dim) |
| Clustering | `scikit-learn` HDBSCAN |
| Frontend | Single HTML file — Tailwind CSS + Alpine.js (no build step) |

---

## For Developers & AI Agents

Before making any changes, read [`docs/agent-instructions.md`](docs/agent-instructions.md).
It contains the full module map, global rules, architecture decisions, and cross-system setup guide.

Track task progress in the task log (see artifact directory).

---

## Team

KH044 Innov8ors | Hackathon Project
