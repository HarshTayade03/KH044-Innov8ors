# Implementation Plan — Contextual Sandbox Validation & LLM-Assisted Prioritization

This plan reconsiders the triage and prioritization architecture to address:
1. **The Role of External LLMs**: Evaluating whether and how external LLMs (e.g. Gemini, OpenAI, Claude) should be used for contextual analysis and vulnerability prioritization.
2. **Pipeline Ordering**: Why **Sandbox Validation must precede Prioritization (and LLM Analysis)** to provide empirical ground truth.
3. **Hybrid Prioritization Architecture**: Combining deterministic mathematical risk scoring with an optional LLM contextual reasoning layer.
4. **Data Privacy & Governance**: Ensuring sensitive vulnerability data and credentials are never leaked to third-party LLMs.

---

## User Review Required

> [!IMPORTANT]
> ### 1. Evaluation: Should We Use External LLMs for Contextual Priority?
>
> | Dimension | Deterministic Engine (Current) | External LLM (e.g., Gemini / GPT) | Recommended Hybrid Model |
> |---|---|---|---|
> | **Contextual Understanding** | Limited to fixed linear weights (CVSS, EPSS, KEV, Asset, Sandbox). | Can reason over business context, code location, parameter type, and sandbox probe/response nuances. | **LLM interprets context; deterministic model guarantees reproducible score baseline.** |
> | **Empirical Ground Truth** | Relies on scanner CVSS + sandbox status. | Can hallucinate exploitability if given only vague scanner text. | **Sandbox executes FIRST** to feed real probe evidence into the LLM, anchoring it to reality. |
> | **Data Privacy & Compliance** | 100% offline; zero data egress. | Vulnerability findings may contain internal hostnames, endpoints, and credentials. | **Strict secret redaction** (`redact_secrets()`) applied before LLM calls; opt-in toggle (`LLM_ENABLED=false` default). |
> | **Offline / CI Portability** | Runs reliably without network or API keys. | Fails if network is isolated or API key is missing. | **Graceful fallback**: If LLM is disabled or fails, deterministic engine completes without interruption. |

> [!IMPORTANT]
> ### 2. Why Sandbox Validation MUST Precede LLM Contextual Prioritization
> If an LLM is asked to prioritize a finding based solely on raw scanner descriptions, it suffers from the same limitation as human analysts: scanner noise, generic descriptions, and unverified claims.
>
> When **Sandbox Validation runs immediately after Deduplication and BEFORE LLM Prioritization**:
> - The LLM receives **empirical evidence**: the exact test probe, parameter reflection, server HTTP response code, error messages, and sandbox logs.
> - The LLM can answer with high precision: *"Did the parameter reflect the probe? Was an error triggered? Did the WAF block it? What is the realistic exploitability in this environment?"*
> - The LLM's contextual analysis is backed by cryptographic evidence artifacts (SHA-256 hashed).

---

## Proposed Architecture

```
                    Raw Scanner Findings
                             ↓
              Stage 1: Normalization & Quality (M1)
                             ↓
              Stage 2: Multi-View Extraction (M2)
                             ↓
              Stage 3: Embeddings & Deduplication (M3)
                             ↓
                 Active Canonical Issues Formed
                             ↓
              Stage 4: Sandbox Validation & Evidence (M5)
                 ├── Safe Lab Simulator (Default offline)
                 ├── Real Docker Sandbox (Optional flag)
                 └── Produces Immutable Redacted Evidence (HTTP probe, response, log, summary)
                             ↓
              Stage 5: Contextual Prioritization (M4)
                 ├── [Engine A] Deterministic Multi-Factor Risk Score (CVSS + EPSS + KEV + Asset + Sandbox Factor)
                 └── [Engine B] LLM Contextual Synthesis (Optional / Hybrid)
                       • Inputs: Multi-Views + Sandbox Evidence Artifacts + Threat Intel + Business Context
                       • Outputs: Exploitability Rationale, Contextual Risk Adjustment, Remediation Guidance
                             ↓
              Stage 6: Analyst Case Review & Approval (M6/M7)
```

---

## Proposed Changes

### 1. Configuration & Privacy Controls

#### [MODIFY] [config.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/config.py)
- Add optional LLM settings with safe offline defaults:
  - `llm_enabled: bool = False` (opt-in feature flag)
  - `llm_provider: str = "gemini"` (`gemini`, `openai`, or `mock`)
  - `llm_model: str = "gemini-1.5-flash"`
  - `llm_api_key: str = ""`

---

### 2. Sandbox Engine & Multi-Artifact Evidence

#### [MODIFY] [sandbox.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/services/sandbox.py)
- Map child CWEs using `resolve_cwe_root()` (e.g. Hibernate SQLi `CWE-564` → `CWE-89`, variant XSS `CWE-80`–`87` → `CWE-79`).
- Normalize target hosts against `settings.sandbox_allowlist_set`.
- Generate 4 immutable evidence artifacts per run:
  1. `http_request`: Simulated probe request.
  2. `http_response`: Simulated server response.
  3. `execution_log`: Container/lab isolation execution trail with timing and allowlist verification.
  4. `validation_summary`: JSON summary of run parameters and verdict.
- Ensure all artifacts pass through `redact_secrets()` and SHA-256 byte hashing.

#### [MODIFY] [validation_repo.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/repositories/validation_repo.py)
- Add `list_for_issue()` and `list_all()` methods.

#### [MODIFY] [validation.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/api/validation.py)
- Add `POST /api/v1/validations/batch` to validate all active canonical issues in one action.
- Add `GET /api/v1/canonical-issues/{canonical_issue_id}/validations` for run history.
- Add `GET /api/v1/validations` for recent run monitoring.

---

### 3. Contextual Prioritization Engine (Deterministic + LLM Hybrid)

#### [MODIFY] [risk_engine.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/services/risk_engine.py)
- **Direct Consumption of Sandbox Results**: Because sandbox validation precedes prioritization:
  - `simulated_match`: Validation factor is set based on confidence (`0.75` to `0.90`), rewarding verified reproducibility and adding contextual justification.
  - `simulated_no_match`: Validation factor drops to `0.20`, actively downgrading non-reproducible vulnerabilities.
  - `inconclusive`: Retains the neutral `0.50` prior.
- **LLM Contextual Synthesis Hook**:
  - If `settings.llm_enabled` is true and API key is present:
    - Pass redacted finding views + sandbox probe/response evidence + threat intel to the LLM service.
    - Receive structured JSON: contextual exploitability rating, business impact narrative, and remediation priority rationale.
    - Store LLM analysis under `factors["llm_context"]` and append summary to the human-readable `explanation`.
  - If LLM is disabled or unavailable:
    - Generate transparent rule-based explanation with zero external dependencies.

#### [NEW] [llm_prioritizer.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/services/llm_prioritizer.py)
- Safe, modular LLM client supporting Gemini/OpenAI providers with strict JSON schema output.
- Enforces pre-call secret redaction and graceful offline fallback.

---

### 4. Frontend Analyst Console (Dashboard)

#### [MODIFY] [index.html](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/static/index.html)
- Reorder workflow track to: `1 · Views` → `2 · Embeddings` → `3 · Deduplicate` → `4 · Sandbox Validate` → `5 · Contextual Prioritize`.
- Add `Validations` table tab alongside Findings, Issues, Clusters.
- Add `Validations` metric counter to top header.

#### [MODIFY] [dashboard.js](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/static/dashboard.js)
- Update `runWorkflow()` to execute in the revised order: Views → Embeddings → Dedup → **Sandbox Validate** → **Prioritize**.
- Add Validation status column in Issues table with color-coded badges and on-demand `Validate` button.
- Add Validations table view with evidence inspect modal.
- In Issue detail modal: display Sandbox Validation card with live probe/response evidence artifacts and LLM contextual synthesis (when enabled).

#### [MODIFY] [dashboard.css](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/src/app/static/dashboard.css)
- Add styling for validation badges, LLM contextual insight cards, and artifact code viewers.

---

### 5. Test Suite Verification

#### [MODIFY] [tests/test_validation.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/tests/test_validation.py)
- Test pipeline order: assert running validation before prioritization sets the real validation factor and updates risk score/tier.
- Test multi-artifact generation and SHA-256 hash integrity.
- Test batch validation endpoint.
- Test host normalization and CWE hierarchy resolution.

#### [MODIFY] [tests/test_cases.py](file:///Users/karanjagtap/Downloads/KH044-Innov8ors/tests/test_cases.py)
- Satisfy foreign key constraints by creating canonical issue fixture before snapshot saving.

---

## Verification Plan

### Automated Tests
```bash
.venv/bin/pytest tests/test_validation.py -v
.venv/bin/pytest tests/ -v
```

### Manual Workflow Verification
1. Start server: `.venv/bin/python -m uvicorn src.app.main:app --port 8000`
2. Open `http://localhost:8000`:
   - Import sample findings.
   - Run "Run core workflow".
   - Confirm sequence: Views → Embeddings → Deduplicate → **Sandbox Validate** → **Prioritize**.
   - Inspect issue: verify that the risk score factors reflect the sandbox outcome (e.g. +7.5 pts for verified SQLi) and evidence artifacts are intact with verified SHA-256 digests.
