DONOT use VULNT-TRIAGER as a product name in public-facing materials. It is a placeholder for internal discussion and prototyping only.

# Product Reference Document

## 1. Product Overview

This is an AI-assisted vulnerability triage and prioritization platform. It collects findings from multiple security tools, converts them into a common format, separates each finding into comparable views, identifies likely duplicates, validates selected findings in an isolated sandbox, enriches them with threat intelligence and business context, generates analyst-ready cases, and keeps final decisions under human control.

```text
Nessus(include Rapid7) ───────┐
Burp Suite ──┤
Snyk ────────┤ → Input & Normalization
Trivy ───────┘              ↓
                    Multi-View Extraction
                             ↓
                    AI Embedding Generation
                             ↓
                    AI-Based Deduplication
                             ↓
                    Sandbox Validation
                             ↓
              Evidence Capture and Preservation
                             ↓
              Threat Intelligence & Prioritization
                             ↓
                    Case Generation
                             ↓
                         Human Review
```

## 2. Product Goal

The product must reduce alert noise, preserve scanner evidence, validate selected findings safely, prioritize real-world risk, and present cases that analysts can approve or reject. Automation supports analysts; it does not replace final human judgment.

## 3. Core Principles

- Preserve original scanner data and evidence.
- Use one unified internal finding schema.
- Never invent missing technical information.
- Keep reported, inferred, and validated information separate.
- Treat scanner alerts as findings, not automatically confirmed vulnerabilities.
- Run potentially dangerous proof-of-concept activity only in an isolated sandbox.
- Keep source provenance for every transformed value.
- Make every automated decision explainable.
- Keep final case approval or rejection human-controlled.

# 4. End-to-End Workflow

## 4.1 Workflow stages

1. Receive findings from Nessus, Burp Suite, Snyk, and Trivy.
2. Normalize scanner-specific output into one common schema.
3. Split each finding into Description, Location, Reproduction, and Impact.
4. Generate embeddings for each view using a Sentence Transformer.
5. Use HDBSCAN and similarity logic to group likely duplicate findings.
6. Merge duplicates into canonical issues while preserving every original source.
7. Select findings for controlled proof-of-concept execution in a Docker sandbox.
8. Mark validation as Confirmed Exploitable, Not Exploitable, or Inconclusive.
9. Store requests, responses, logs, crash traces, and PoC results as evidence.
10. Enrich findings using CISA KEV, EPSS, CVSS, asset criticality, and network exposure.
11. Assign remediation tiers: Immediate, Accelerated, or Standard.
12. Generate analyst-ready cases.
13. Let analysts approve or reject cases through the dashboard.

## 4.2 State flow

```text
RECEIVED
  ↓
NORMALIZED / NORMALIZED_WITH_WARNINGS / REJECTED
  ↓
VIEWS_EXTRACTED
  ↓
EMBEDDINGS_GENERATED
  ↓
CLUSTERED / CANONICALIZED
  ↓
VALIDATION_PENDING
  ↓
CONFIRMED_EXPLOITABLE / NOT_EXPLOITABLE / INCONCLUSIVE
  ↓
RISK_PRIORITIZED
  ↓
CASE_GENERATED
  ↓
ANALYST_APPROVED / ANALYST_REJECTED
```

# 5. Suggested Technology Architecture

## 5.1 Prototype stack

- Backend: Python and FastAPI.
- Validation: Pydantic.
- Database: SQLite for the prototype.
- Persistence: JSON columns or serialized structured fields where necessary.
- Embeddings: Sentence Transformers.
- Clustering: HDBSCAN.
- Sandbox: Docker containers with strict controls.
- Frontend: Any simple dashboard framework suitable for the team.
- Background work: Lightweight task queue or background worker; synchronous processing is acceptable for small demo data.

## 5.2 Suggested repository structure

```text
vulntriager/
├── src/
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── api/
│       ├── schemas/
│       ├── parsers/
│       ├── services/
│       ├── models/
│       ├── repositories/
│       ├── mappings/
│       ├── workers/
│       └── security/
├── data/
├── tests/
├── docker/
├── requirements.txt
├── README.md
└── .env.example
```

# 6. Module 1: Input and Normalization

## 6.1 Purpose

The Input and Normalization Module is the entry point. It receives scanner findings, detects or accepts the scanner type, parses each format, maps fields to a unified schema, cleans and validates values, preserves raw evidence, and forwards accepted findings to Multi-View Extraction.

It hides scanner-specific differences from every later module.

## 6.2 Supported sources

- Nessus.
- Burp Suite.
- Snyk.
- Trivy.

The prototype should support representative JSON structures for each source. It does not need to support every official export variation in the first version.

## 6.3 Input methods

### JSON upload

```http
POST /api/v1/findings/upload
Content-Type: multipart/form-data
```

Fields:

```text
file: JSON file
source_scanner: nessus | burp | snyk | trivy
```

### Direct JSON API

```http
POST /api/v1/findings
Content-Type: application/json
```

### Synthetic data

Maintain sample files:

```text
data/
├── nessus_sample.json
├── burp_sample.json
├── snyk_sample.json
└── trivy_sample.json
```

Include complete, incomplete, inconsistent, and invalid examples.

## 6.4 Example input formats

### Nessus

```json
{
  "plugin_id": "19506",
  "plugin_name": "Apache HTTP Server Vulnerability",
  "host": "10.0.0.15",
  "port": 443,
  "protocol": "tcp",
  "cve": ["CVE-2024-1234"],
  "cvss_base_score": 8.8,
  "severity": "High",
  "description": "The installed Apache version is vulnerable.",
  "solution": "Upgrade Apache to the latest secure version.",
  "plugin_output": "Detected version: 2.4.49"
}
```

### Burp Suite

```json
{
  "issue_id": "burp-1001",
  "name": "SQL Injection",
  "host": "https://app.example.test",
  "path": "/api/login",
  "parameter": "username",
  "severity": "High",
  "confidence": "Certain",
  "issue_background": "The username parameter is vulnerable to SQL injection.",
  "request": "POST /api/login",
  "response": "HTTP/1.1 200 OK",
  "evidence": "Payload changed the response behavior."
}
```

### Snyk

```json
{
  "id": "SNYK-JAVA-LOG4J-123456",
  "package_name": "log4j-core",
  "package_version": "2.14.1",
  "fixed_in": ["2.17.1"],
  "cve": "CVE-2021-44228",
  "severity": "Critical",
  "cvss_score": 10.0,
  "file": "pom.xml",
  "description": "A vulnerable version of log4j-core is present.",
  "package_manager": "maven"
}
```

### Trivy

```json
{
  "target": "auth-service:1.0.0",
  "type": "library",
  "vulnerability_id": "CVE-2023-4567",
  "pkg_name": "openssl",
  "installed_version": "1.1.1",
  "fixed_version": "1.1.1w",
  "severity": "High",
  "title": "OpenSSL vulnerability",
  "description": "The installed package is affected by a known vulnerability.",
  "primary_url": "https://example.test/advisory/CVE-2023-4567"
}
```

## 6.5 Unified normalized finding schema

```json
{
  "finding_id": "f-uuid-001",
  "source_scanner": "burp",
  "source_finding_id": "burp-1001",
  "ingestion_batch_id": "batch-uuid-001",
  "ingested_at": "2026-09-11T12:00:00Z",
  "vulnerability": {
    "cve_ids": [],
    "cwe_ids": ["CWE-89"],
    "title": "SQL Injection",
    "description": "The username parameter is vulnerable to SQL injection.",
    "severity": "High",
    "cvss_score": null,
    "confidence": "Certain"
  },
  "asset": {
    "asset_id": null,
    "asset_name": "app.example.test",
    "asset_type": "web_application",
    "environment": "lab",
    "internet_facing": false,
    "criticality": "high"
  },
  "location": {
    "host": "app.example.test",
    "port": null,
    "protocol": "https",
    "url": "https://app.example.test/api/login",
    "path": "/api/login",
    "parameter": "username",
    "file": null,
    "package": null,
    "container_image": null,
    "function": null,
    "installed_version": null
  },
  "evidence": {
    "summary": "Payload changed the response behavior.",
    "request": "POST /api/login",
    "response": "HTTP/1.1 200 OK",
    "payload": null,
    "raw_output": "Payload changed the response behavior.",
    "code_snippet": null
  },
  "remediation": {
    "recommendation": null,
    "fixed_version": null,
    "reference_urls": []
  },
  "provenance": {
    "source_file": "burp_sample.json",
    "parser_name": "BurpParser",
    "parser_version": "1.0.0",
    "raw_record_hash": "sha256:...",
    "original_data": {}
  },
  "quality": {
    "normalization_status": "normalized",
    "completeness_score": 0.92,
    "warnings": [],
    "errors": []
  }
}
```

## 6.6 Parser architecture

Create one parser per scanner:

```text
BaseScannerParser
├── NessusParser
├── BurpParser
├── SnykParser
└── TrivyParser
```

Interface:

```python
class BaseScannerParser:
    scanner_name: str

    def parse(self, raw_record: dict) -> dict:
        raise NotImplementedError
```

Registry:

```python
PARSER_REGISTRY = {
    "nessus": NessusParser(),
    "burp": BurpParser(),
    "snyk": SnykParser(),
    "trivy": TrivyParser(),
}
```

Each parser returns an intermediate object; the common normalizer builds the final schema.

## 6.7 Normalization rules

### CVE

Normalize values such as `cve-2024-1234`, `CVE 2024 1234`, and CVE URLs to `CVE-2024-1234`. Store multiple identifiers as an array and remove duplicates.

### CWE

Normalize `89`, `CWE89`, and `cwe-89` to `CWE-89`.

### Severity

Allowed values:

```text
Critical
High
Medium
Low
Informational
Unknown
```

### CVSS

Convert to a number from 0 to 10. Invalid values become `null` with a warning. Missing CVSS is not the same as a score of zero.

### Assets and locations

Trim whitespace, normalize hostnames, preserve complete URLs, normalize paths, and retain meaningful endpoint, package, file, port, and parameter differences.

### Text

Clean whitespace and unnecessary markup, but do not alter payloads, request syntax, response syntax, URLs, code, or evidence meaning.

## 6.8 Validation

Required or strongly recommended values:

- Internal finding ID.
- Supported scanner.
- Asset name or target.
- Title or description.
- Severity, using `Unknown` if absent.
- Evidence object.
- Original raw record.

Validate CVE pattern, CWE pattern, CVSS range, port range, URL syntax where supplied, and expected data types.

Statuses:

- `normalized`: usable and sufficiently complete.
- `normalized_with_warnings`: usable but incomplete or inconsistent.
- `rejected`: unsafe or impossible to interpret.

One invalid record must not stop an entire batch.

## 6.9 Provenance

Preserve scanner name, original finding ID, source file, batch ID, parser name/version, timestamp, raw record, and raw record hash.

Hash code:

```python
import hashlib
import json

def hash_raw_record(record: dict) -> str:
    serialized = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()
```

## 6.10 Module 1 APIs

```http
GET /health
POST /api/v1/findings/upload
POST /api/v1/findings
GET /api/v1/findings
GET /api/v1/findings/{finding_id}
GET /api/v1/ingestion/batches/{batch_id}
```

Batch response:

```json
{
  "batch_id": "batch-001",
  "source_scanner": "nessus",
  "total_received": 100,
  "normalized": 92,
  "normalized_with_warnings": 7,
  "rejected": 1,
  "status": "completed",
  "next_stage": "multi_view_extraction"
}
```

# 7. Module 2: Multi-View Extraction

## 7.1 Purpose

This module receives normalized findings and separates them into four comparable views:

1. Description: what the vulnerability is.
2. Location: where it exists.
3. Reproduction: how it was observed or triggered.
4. Impact: what an attacker could potentially achieve.

These views are prepared for embedding generation and deduplication.

## 7.2 Output schema

```json
{
  "finding_id": "f-001",
  "views": {
    "description": {
      "text": "SQL injection affecting the username parameter.",
      "structured": {},
      "source": ["vulnerability.title", "vulnerability.description"],
      "extraction_method": "structured_fields",
      "confidence": 0.98,
      "status": "available",
      "warnings": []
    },
    "location": {
      "text": "app.example.test /api/login parameter username",
      "structured": {
        "asset_name": "app.example.test",
        "host": "app.example.test",
        "path": "/api/login",
        "parameter": "username"
      },
      "source": ["asset.asset_name", "location.path", "location.parameter"],
      "extraction_method": "structured_fields",
      "confidence": 1.0,
      "status": "available",
      "warnings": []
    },
    "reproduction": {
      "text": "Send POST request to /api/login with the reported payload in username.",
      "structured": {
        "method": "POST",
        "endpoint": "/api/login",
        "parameter": "username",
        "payload": "' OR '1'='1",
        "request": "POST /api/login",
        "observed_behavior": "Payload changed the response behavior."
      },
      "source": ["evidence.request", "evidence.payload", "evidence.summary"],
      "extraction_method": "structured_fields_and_rules",
      "confidence": 0.94,
      "status": "available",
      "warnings": []
    },
    "impact": {
      "text": "Potential authentication bypass and unauthorized access.",
      "structured": {
        "impact_type": ["authentication_bypass", "unauthorized_access"]
      },
      "source": ["vulnerability.description", "inferred_from_cwe"],
      "extraction_method": "rule_based_inference",
      "confidence": 0.72,
      "status": "inferred",
      "warnings": []
    }
  },
  "embedding_text": {
    "description": "SQL injection affecting the username parameter.",
    "location": "app.example.test https /api/login parameter username",
    "reproduction": "POST /api/login username payload reported",
    "impact": "potential authentication bypass unauthorized access"
  },
  "view_quality": {
    "available_views": 4,
    "missing_views": [],
    "warnings": []
  }
}
```

## 7.3 Extraction strategy

Use this priority order:

1. Structured normalized fields.
2. Scanner evidence fields.
3. Deterministic parsing and regular expressions.
4. Controlled CWE and keyword mappings.
5. Optional LLM assistance.
6. Missing value.

Do not claim independent validation. Reproduction records scanner-reported behavior only.

## 7.4 Description extraction

Use title, description, CWE, and CVE context. Remove duplicated boilerplate while preserving vulnerability class, affected component, and meaningful technical terms.

## 7.5 Location extraction

Use asset and location fields. Preserve hostname, IP, port, protocol, URL, path, parameter, file, package, image, and function. Create a canonical text representation for embeddings while preserving structured fields.

## 7.6 Reproduction extraction

Use requests, responses, payloads, commands, scanner output, and observed behavior. Extract HTTP method, endpoint, parameter, payload, request, response, and steps where present. If absent, return a missing view instead of generating a fake procedure.

## 7.7 Impact extraction

Use explicit impact fields first. Then use description keywords, scanner title, CWE mapping, CVSS impact data, and evidence behavior. Use controlled impact types:

```text
authentication_bypass
unauthorized_access
data_disclosure
sensitive_information_exposure
remote_code_execution
command_execution
privilege_escalation
arbitrary_file_read
arbitrary_file_write
denial_of_service
cross_site_scripting
server_side_request_forgery
container_escape
dependency_compromise
integrity_violation
availability_impact
unknown
```

Always label inferred impact as potential or inferred until sandbox validation.

## 7.8 View statuses

- `available`: reliable information exists.
- `partial`: some information exists.
- `inferred`: derived from rules or indirect context.
- `missing`: no reliable information.
- `conflicting`: sources disagree.

Extraction methods may be `structured_fields`, `structured_fields_and_rules`, `regex_extraction`, `keyword_inference`, `llm_assisted`, or `missing`.

## 7.9 Sensitive-data handling

Before creating embedding text, redact API keys, passwords, cookies, authorization headers, bearer tokens, and personal information. Preserve original evidence separately and unchanged.

Example:

```text
Authorization: Bearer <REDACTED>
```

## 7.10 Optional LLM extraction

If an LLM is used, require JSON output, validate it with Pydantic, use low temperature, preserve source fields, store model metadata, and require `null` when a value is absent. The prompt must explicitly prohibit invention and claims of confirmed exploitation.

## 7.11 Module 2 APIs

```http
POST /api/v1/findings/{finding_id}/extract-views
POST /api/v1/batches/{batch_id}/extract-views
GET /api/v1/findings/{finding_id}/views
```

# 8. Module 3: AI Embedding Generation

## 8.1 Purpose

This module converts the four extracted views into numerical vectors using a Sentence Transformer. Embeddings allow the system to compare findings by meaning rather than exact wording.

```text
Description text ───────┐
Location text ──────────┤
Reproduction text ──────┤ → Sentence Transformer → View embeddings
Impact text ────────────┘
```

## 8.2 Input

```json
{
  "finding_id": "f-001",
  "embedding_text": {
    "description": "SQL injection affecting the username parameter.",
    "location": "app.example.test https /api/login parameter username",
    "reproduction": "POST /api/login username payload reported",
    "impact": "potential authentication bypass unauthorized access"
  },
  "view_quality": {
    "available_views": 4,
    "missing_views": [],
    "warnings": []
  }
}
```

## 8.3 Output

```json
{
  "finding_id": "f-001",
  "embedding_model": "sentence-transformers-model-name",
  "model_version": "version",
  "embedding_dimension": 384,
  "embeddings": {
    "description": [0.01, -0.02],
    "location": [0.03, 0.04],
    "reproduction": [-0.01, 0.02],
    "impact": [0.05, -0.03]
  },
  "combined_embedding": [0.01, -0.02],
  "generated_at": "2026-09-11T12:00:00Z",
  "missing_views": []
}
```

The actual vectors contain the full model dimension; shortened vectors above are illustrative only.

## 8.4 Recommended embedding strategy

Generate one embedding per view:

- Description embedding.
- Location embedding.
- Reproduction embedding.
- Impact embedding.

Optionally generate a combined embedding from weighted concatenated text or a weighted average.

Do not concatenate raw vectors unless dimensions and downstream distance behavior are intentionally designed. A safer prototype approach is to store separate vectors and calculate a weighted similarity score.

## 8.5 Missing views

If a view is missing, do not embed the string `null` as if it were meaningful content. Store a missing flag and either omit the view from scoring or apply a controlled neutral policy.

## 8.6 Model metadata

Store:

- Model name.
- Model version.
- Embedding dimension.
- Normalization setting.
- Generation timestamp.
- Input text hash.

Embeddings must be reproducible for the same model and input text.

## 8.7 Similarity preparation

Use cosine similarity for normalized vectors:

\[
\operatorname{cosine}(a,b)=\frac{a\cdot b}{\|a\|\|b\|}
\]

A later deduplication stage can calculate a weighted score:

\[
S = w_d S_d + w_l S_l + w_r S_r + w_i S_i
\]

where:

- \(S_d\) is description similarity.
- \(S_l\) is location similarity.
- \(S_r\) is reproduction similarity.
- \(S_i\) is impact similarity.
- Weights must be configurable.

For security findings, location should usually be treated as a strong constraint rather than relying on description similarity alone.

# 9. Module 4: AI-Based Deduplication

## 9.1 Purpose

This module identifies alerts that describe the same underlying issue, groups similar findings, and creates a canonical issue while preserving all original sources.

```text
View embeddings + structured identifiers
        ↓
Similarity calculation
        ↓
HDBSCAN clustering
        ↓
Cluster review rules
        ↓
Canonical issue creation
```

## 9.2 Why clustering alone is insufficient

Two findings may have similar descriptions but affect different endpoints, assets, packages, or versions. HDBSCAN should propose groups, but deterministic constraints and analyst review should prevent unsafe merges.

## 9.3 Similarity inputs

Use:

- Description embedding.
- Location embedding.
- Reproduction embedding.
- Impact embedding.
- CVE IDs.
- CWE IDs.
- Asset identity.
- Endpoint or package identity.
- Container image.
- Source scanner.
- Version information.

## 9.4 HDBSCAN behavior

HDBSCAN groups dense regions without requiring a fixed number of clusters and can mark uncertain points as noise. Its parameters must be configurable:

- `min_cluster_size`.
- `min_samples`.
- Distance metric.
- Cluster selection method.

The system must store parameter values for reproducibility.

## 9.5 Recommended merge logic

A candidate merge should require semantic similarity plus compatibility checks.

Possible rules:

- Same CVE and same asset or component: strong merge candidate.
- Same CWE and same endpoint with high view similarity: candidate.
- Same package and vulnerable version range: candidate.
- Same title but different endpoint: do not automatically merge.
- Same vulnerability on different assets: keep separate unless the product explicitly defines an asset-group issue.
- Conflicting vulnerability classes: do not merge automatically.
- Different package names: do not merge solely because descriptions are similar.

## 9.6 Canonical issue

A canonical issue must contain:

```json
{
  "canonical_issue_id": "ci-001",
  "title": "SQL Injection in /api/login username parameter",
  "canonical_description": "...",
  "asset_scope": [],
  "location_scope": [],
  "source_findings": ["f-001", "f-045"],
  "source_scanners": ["burp", "nessus"],
  "cluster_id": "cluster-12",
  "similarity_score": 0.91,
  "merge_reason": ["same endpoint", "same vulnerability class"],
  "merge_confidence": 0.88,
  "review_status": "pending"
}
```

Never discard original findings. Store a many-to-one relationship between source findings and canonical issues.

## 9.7 Duplicate statuses

- `candidate`: algorithm suggests similarity.
- `merged`: canonical issue created.
- `kept_separate`: reviewed or rule-blocked.
- `uncertain`: insufficient evidence.
- `rejected_merge`: analyst rejected the merge.

## 9.8 Analyst visibility

Show:

- All alerts in the cluster.
- Source scanner for each alert.
- Similarity by view.
- Shared and differing locations.
- CVE/CWE comparison.
- Merge explanation.
- Original evidence links.

# 10. Module 5: Sandbox Validation

## 10.1 Purpose

Sandbox Validation executes selected proof-of-concept checks in an isolated Docker environment to determine whether a finding can be reproduced under controlled conditions.

Possible outcomes:

- `confirmed_exploitable`
- `not_exploitable`
- `inconclusive`

A scanner alert must not be marked confirmed merely because a PoC was selected. Confirmation requires controlled execution evidence.

## 10.2 Safety goals

- Never run PoC code directly on the host.
- Use an isolated container.
- Apply CPU, memory, time, process, file, and network limits.
- Use an allowlisted target.
- Prevent access to cloud metadata and internal networks.
- Use non-production test systems only.
- Require explicit authorization for execution.
- Record all execution events.

## 10.3 Validation input

```json
{
  "canonical_issue_id": "ci-001",
  "finding_id": "f-001",
  "poc_type": "http_request",
  "target": {
    "url": "https://app.example.test/api/login",
    "allowlisted": true
  },
  "steps": [
    {
      "method": "POST",
      "path": "/api/login",
      "parameter": "username",
      "payload_reference": "stored-payload-001"
    }
  ],
  "timeout_seconds": 30
}
```

Do not place secrets directly in logs or prompts. Use protected references.

## 10.4 Execution controls

At minimum:

- Non-root container user.
- Read-only root filesystem where possible.
- Temporary writable directory.
- CPU limit.
- Memory limit.
- PID limit.
- Execution timeout.
- Network egress allowlist.
- No privileged mode.
- No host networking.
- No host filesystem mounts.
- No Docker socket.
- No access to cloud metadata endpoints.
- Automatic cleanup after execution.

## 10.5 Validation result

```json
{
  "validation_id": "val-001",
  "canonical_issue_id": "ci-001",
  "finding_id": "f-001",
  "status": "confirmed_exploitable",
  "confidence": 0.94,
  "executed_at": "2026-09-11T12:00:00Z",
  "sandbox_image": "vulntriager/poc-runner:1.0",
  "execution_summary": "The controlled request produced the expected vulnerable behavior.",
  "evidence_ids": ["ev-001", "ev-002", "ev-003"],
  "warnings": []
}
```

## 10.6 Result interpretation

### Confirmed Exploitable

The PoC ran successfully and produced an expected vulnerability-specific result with sufficient evidence.

### Not Exploitable

The PoC ran successfully but the expected vulnerable behavior was not observed, or the necessary condition was absent.

### Inconclusive

Execution failed, environment was incomplete, evidence was ambiguous, or the result could not safely establish exploitability.

Do not equate a timeout or infrastructure error with Not Exploitable.

# 11. Module 6: Evidence Capture

## 11.1 Purpose

Evidence Capture stores supporting artifacts from ingestion, extraction, deduplication, sandbox validation, and prioritization.

## 11.2 Evidence types

- Original scanner record.
- Raw scanner output.
- HTTP request.
- HTTP response.
- Payload reference.
- PoC script hash.
- Container logs.
- Execution logs.
- Standard output.
- Standard error.
- Crash trace.
- Exit code.
- Screenshots or artifacts.
- Validation summary.
- Threat intelligence response.
- Risk calculation inputs.

## 11.3 Evidence schema

```json
{
  "evidence_id": "ev-001",
  "entity_type": "validation",
  "entity_id": "val-001",
  "evidence_type": "http_response",
  "content_reference": "object-storage-key-or-inline-reference",
  "content_hash": "sha256:...",
  "content_size": 1234,
  "redacted": true,
  "created_at": "2026-09-11T12:00:00Z",
  "metadata": {
    "status_code": 200,
    "content_type": "application/json"
  }
}
```

## 11.4 Evidence rules

- Never overwrite evidence.
- Store immutable references.
- Hash artifacts.
- Redact secrets before analyst display.
- Keep original protected artifacts if policy permits.
- Link every artifact to a finding, canonical issue, validation, or case.
- Record who or what generated the artifact.

# 12. Module 7: Threat Intelligence and Prioritization

## 12.1 Purpose

This module converts technical findings into real-world risk by combining vulnerability severity, exploitation activity, likelihood, asset importance, and exposure.

Inputs include:

- CISA KEV status.
- EPSS score.
- CVSS score.
- Asset criticality.
- Network exposure.
- Validation status.
- Confidence and evidence quality.
- Business environment.

## 12.2 Important distinction

CVSS describes technical severity. It does not by itself describe real-world priority. Prioritization should combine multiple signals.

## 12.3 Suggested risk inputs

```json
{
  "cvss_score": 8.8,
  "epss_score": 0.72,
  "cisa_kev": true,
  "asset_criticality": "high",
  "internet_facing": true,
  "validation_status": "confirmed_exploitable",
  "finding_confidence": 0.94,
  "data_quality": 0.92
}
```

## 12.4 Risk calculation

Use a configurable, explainable score. For example, normalize each input to 0–1:

```text
technical_severity = cvss_score / 10
exploit_likelihood = epss_score
kev_signal = 1 if CISA KEV else 0
asset_factor = mapping(asset criticality)
exposure_factor = 1.0 for internet-facing, lower for internal assets
validation_factor = mapping(validation status)
```

A configurable weighted score may be:

\[
R = 100 \times (w_c C + w_e E + w_k K + w_a A + w_x X + w_v V)
\]

where:

- \(C\) = normalized CVSS.
- \(E\) = EPSS.
- \(K\) = KEV indicator.
- \(A\) = asset criticality.
- \(X\) = network exposure.
- \(V\) = validation factor.
- Weights must be stored with every calculation.

This is a product scoring model, not a universal security standard. The UI must show the input values and contribution of each factor.

## 12.5 Remediation tiers

### Immediate

Use for combinations such as:

- Confirmed exploitable and internet-facing.
- CISA KEV vulnerability on a critical asset.
- High technical severity with strong exploit likelihood and high asset criticality.
- Remote code execution or authentication bypass with material exposure.

### Accelerated

Use for:

- High or critical severity.
- High EPSS but not confirmed.
- Important internal asset.
- Significant impact with moderate exposure.

### Standard

Use for:

- Lower severity.
- Low exploit likelihood.
- Limited asset criticality.
- No meaningful exposure.
- Findings needing normal remediation planning.

Rules must be configurable rather than hardcoded in UI logic.

## 12.6 Prioritization output

```json
{
  "priority_id": "pri-001",
  "canonical_issue_id": "ci-001",
  "risk_score": 91.4,
  "remediation_tier": "Immediate",
  "factors": {
    "cvss": 8.8,
    "epss": 0.72,
    "cisa_kev": true,
    "asset_criticality": "high",
    "internet_facing": true,
    "validation_status": "confirmed_exploitable"
  },
  "explanation": [
    "The vulnerability is present in CISA KEV.",
    "The asset is internet-facing.",
    "The finding was confirmed exploitable.",
    "The asset has high business criticality."
  ],
  "calculation_version": "risk-model-1.0"
}
```

# 13. Module 8: Analyst-Ready Case Generation

## 13.1 Purpose

This module transforms a canonical issue, its merged findings, evidence, validation result, risk score, and remediation recommendation into a case an analyst can understand and act on.

## 13.2 Case contents

Every case should contain:

- Case ID.
- Canonical issue ID.
- Title.
- Executive summary.
- Technical description.
- Affected assets.
- Exact locations.
- Reproduction information.
- Potential impact.
- Validation status.
- Evidence links.
- Merged source findings.
- Scanner names.
- CVE/CWE.
- CVSS and EPSS.
- CISA KEV status.
- Asset criticality.
- Network exposure.
- Risk score.
- Remediation tier.
- Remediation recommendation.
- Fixed version where applicable.
- Analyst status.
- Audit history.

## 13.3 Case schema

```json
{
  "case_id": "case-001",
  "canonical_issue_id": "ci-001",
  "status": "pending_review",
  "title": "Confirmed SQL Injection in Login API",
  "summary": "A SQL injection finding reported by Burp and Nessus affects the login API.",
  "technical_details": {},
  "affected_assets": [],
  "locations": [],
  "reproduction": {},
  "impact": {},
  "validation": {},
  "source_findings": ["f-001", "f-045"],
  "evidence_ids": ["ev-001", "ev-002"],
  "priority": {},
  "remediation": {
    "recommendation": "Use parameterized queries and deploy the fixed code.",
    "fixed_version": null
  },
  "review": {
    "status": "pending",
    "reviewer_id": null,
    "reviewed_at": null,
    "review_comment": null
  },
  "created_at": "2026-09-11T12:00:00Z"
}
```

## 13.4 Case generation rules

- Use the canonical issue as the central identity.
- Include every merged source finding.
- Preserve conflicting values instead of silently hiding them.
- Clearly distinguish reported and confirmed evidence.
- Show why the case received its priority.
- Make recommendations actionable.
- Do not automatically mark the case approved.

# 14. Module 9: Human Review

## 14.1 Purpose

Human Review ensures that final decisions remain under analyst control. Analysts inspect cases, evidence, duplicate grouping, validation, prioritization, and remediation before approving or rejecting a case.

## 14.2 Review actions

- Approve case.
- Reject case.
- Request more evidence.
- Mark duplicate.
- Separate wrongly merged findings.
- Change priority with a reason.
- Change remediation tier with a reason.
- Add analyst comment.
- Assign owner.
- Set due date.

## 14.3 Review schema

```json
{
  "review_id": "review-001",
  "case_id": "case-001",
  "decision": "approved",
  "reviewer_id": "analyst-007",
  "comment": "Evidence and validation are sufficient.",
  "reviewed_at": "2026-09-11T12:00:00Z",
  "previous_status": "pending_review",
  "new_status": "approved"
}
```

## 14.4 Approval rules

- The system must not silently approve cases.
- Rejection requires a reason.
- Manual risk changes require a reason.
- Merge and split actions must be audited.
- Evidence shown to analysts must retain provenance.
- Case history must be immutable or append-only.

## 14.5 Dashboard views

### Overview

- Total findings.
- Normalized findings.
- Duplicate clusters.
- Pending validation.
- Confirmed exploitable findings.
- Immediate cases.
- Cases pending review.

### Case list

Filters:

- Status.
- Severity.
- Remediation tier.
- Source scanner.
- Asset criticality.
- Internet exposure.
- Validation result.
- CVE.
- CWE.

### Case detail

Show:

- Summary and title.
- Risk score and explanation.
- Affected assets.
- Description, location, reproduction, and impact.
- Validation result.
- Evidence.
- Duplicate cluster members.
- Original scanner findings.
- Remediation.
- Review actions.
- Audit timeline.

# 15. Core Database Model

For SQLite, use tables such as:

```text
scanner_findings
normalized_findings
finding_views
finding_embeddings
clusters
canonical_issues
cluster_members
validation_runs
artifacts
threat_intelligence
priorities
cases
reviews
audit_events
```

## 15.1 Relationships

```text
scanner_findings 1 → 1 normalized_findings
normalized_findings 1 → many finding_views
normalized_findings 1 → many finding_embeddings
canonical_issues 1 → many normalized_findings
canonical_issues 1 → many validation_runs
validation_runs 1 → many artifacts
canonical_issues 1 → 1 priority
canonical_issues 1 → 1 case
cases 1 → many reviews
all major entities → many audit_events
```

## 15.2 Important database fields

Every major table should include:

- Internal ID.
- Creation timestamp.
- Update timestamp.
- Status.
- Provenance or source reference where relevant.
- Version or calculation version where relevant.

# 16. API Surface

## Ingestion

```http
POST /api/v1/findings/upload
POST /api/v1/findings
GET /api/v1/findings
GET /api/v1/findings/{finding_id}
GET /api/v1/ingestion/batches/{batch_id}
```

## Multi-view extraction

```http
POST /api/v1/findings/{finding_id}/extract-views
POST /api/v1/batches/{batch_id}/extract-views
GET /api/v1/findings/{finding_id}/views
```

## Embeddings

```http
POST /api/v1/findings/{finding_id}/generate-embeddings
POST /api/v1/batches/{batch_id}/generate-embeddings
GET /api/v1/findings/{finding_id}/embeddings
```

## Deduplication

```http
POST /api/v1/deduplication/run
GET /api/v1/clusters
GET /api/v1/clusters/{cluster_id}
POST /api/v1/clusters/{cluster_id}/merge
POST /api/v1/clusters/{cluster_id}/split
```

## Validation

```http
POST /api/v1/canonical-issues/{canonical_issue_id}/validate
GET /api/v1/validations/{validation_id}
GET /api/v1/validations/{validation_id}/evidence
```

## Prioritization

```http
POST /api/v1/canonical-issues/{canonical_issue_id}/prioritize
GET /api/v1/priorities
```

## Cases and reviews

```http
POST /api/v1/canonical-issues/{canonical_issue_id}/generate-case
GET /api/v1/cases
GET /api/v1/cases/{case_id}
POST /api/v1/cases/{case_id}/approve
POST /api/v1/cases/{case_id}/reject
POST /api/v1/cases/{case_id}/request-evidence
```

# 17. Security and Privacy Requirements

- Use authentication and role-based authorization outside the simplest demo if possible.
- Separate analyst, administrator, and execution permissions.
- Require explicit permission for sandbox runs.
- Never expose secrets in embeddings or dashboard text.
- Redact secrets from logs.
- Protect raw evidence.
- Restrict Docker access.
- Validate all uploaded files.
- Limit file size and JSON nesting.
- Prevent path traversal.
- Use safe serialization.
- Store audit events for state changes.
- Avoid network access from PoC containers except allowlisted targets.

# 18. Error Handling

## User-correctable errors

Return clear messages for:

- Invalid JSON.
- Unsupported scanner.
- Missing file.
- Empty batch.
- Invalid field types.
- Failed extraction.
- Missing target authorization.

## Processing errors

- Record the failed item.
- Continue processing independent records.
- Set an appropriate status.
- Preserve the input record.
- Add an audit or error event.
- Avoid leaking stack traces to ordinary users.

# 19. Observability

Track:

- Batch processing time.
- Number of records by scanner.
- Normalization success and rejection counts.
- View extraction success and missing-view counts.
- Embedding generation time.
- Number of clusters and noise points.
- Validation success/failure/timeouts.
- Prioritization runs.
- Case approval/rejection counts.

Use structured logs with correlation IDs:

```text
request_id
batch_id
finding_id
canonical_issue_id
validation_id
case_id
```

# 20. Testing Strategy

## Unit tests

- Each scanner parser.
- CVE/CWE normalization.
- Severity and CVSS normalization.
- Location parsing.
- Evidence preservation.
- Description, location, reproduction, and impact extraction.
- Secret redaction.
- Embedding input preparation.
- Similarity calculation.
- Risk calculation.
- Case generation.

## Integration tests

- Upload a scanner file through the API.
- Normalize and store findings.
- Extract views.
- Generate embeddings.
- Run clustering.
- Create a canonical issue.
- Run mocked validation.
- Calculate priority.
- Generate case.
- Approve or reject through review API.

## Safety tests

- Reject unauthorized sandbox target.
- Enforce timeout.
- Enforce resource limits.
- Prevent privileged containers.
- Redact credentials.
- Prevent raw secret display.

# 21. Hackathon MVP Plan

## Must demonstrate

1. Upload representative findings from all four scanners.
2. Display normalized unified records.
3. Display four extracted views.
4. Generate embeddings.
5. Show duplicate grouping with at least two similar findings.
6. Display merged canonical issue and source provenance.
7. Run a safe mocked or controlled PoC in Docker.
8. Display validation result and evidence.
9. Calculate a transparent priority.
10. Generate an analyst-ready case.
11. Approve or reject the case manually.

## Keep simple

- Use JSON sample data rather than live scanner integrations.
- Use SQLite.
- Use a small Sentence Transformer model.
- Use HDBSCAN with configurable defaults.
- Use mocked threat intelligence if live APIs are unavailable, but label mock data clearly.
- Use a safe demonstration target for sandbox validation.
- Use a simple dashboard with case and cluster views.

# 22. Definition of Done

The product prototype is complete when:

- All four input sources can be ingested.
- All accepted findings use the same schema.
- Original evidence is preserved.
- Findings are split into four views.
- Views can be embedded.
- Similar findings can be clustered.
- Clusters produce canonical issues without losing source findings.
- Selected issues can be validated safely.
- Validation results and artifacts are stored.
- Risk score and remediation tier are explainable.
- Cases contain all relevant details and evidence.
- Analysts can approve or reject cases.
- All important automated actions are auditable.
- The system never treats inference as confirmation.

# 23. Consolidated AI Coding Prompt

```text
You are building VulnTriager, an AI-assisted vulnerability triage platform.

Build a modular Python FastAPI application using Pydantic and SQLite for the prototype. The application must implement this pipeline:

1. Input and normalization.
2. Multi-view extraction.
3. Sentence Transformer embeddings.
4. HDBSCAN-based deduplication.
5. Canonical issue generation.
6. Controlled Docker sandbox validation.
7. Evidence capture.
8. Threat intelligence and prioritization.
9. Analyst-ready case generation.
10. Human review and approval/rejection.

Input and normalization:
- Accept JSON files and direct JSON API submissions.
- Support Nessus, Burp Suite, Snyk, and Trivy representative formats.
- Create one parser per scanner.
- Normalize every record into a common schema containing finding identity, source, CVE, CWE, title, description, severity, CVSS, asset, location, evidence, remediation, provenance, and quality.
- Preserve original raw data and evidence.
- Normalize CVE, CWE, severity, CVSS, asset, and location values.
- Do not fabricate missing values.
- Continue processing a batch when one record fails.
- Return batch summaries and clear validation warnings.

Multi-view extraction:
- Split every normalized finding into Description, Location, Reproduction, and Impact.
- Prefer structured fields, then scanner evidence, then deterministic rules, then controlled keyword/CWE inference.
- Clearly mark each view as available, partial, inferred, missing, or conflicting.
- Store confidence, source fields, extraction method, and warnings.
- Never invent payloads, locations, impacts, or exploitability.
- Redact secrets before producing embedding text.

Embeddings:
- Use Sentence Transformers.
- Create separate embeddings for all four views.
- Store model metadata, dimension, input hash, and generation time.
- Handle missing views explicitly.
- Use cosine similarity and configurable weighted view scores.

Deduplication:
- Use HDBSCAN for candidate clustering.
- Combine embedding similarity with CVE/CWE, asset, endpoint, package, version, and container identity.
- Do not merge solely because descriptions are similar.
- Create canonical issues containing merged source finding IDs, scanner sources, merge reason, similarity, and confidence.
- Preserve every original finding.
- Allow analyst merge, split, and rejection decisions.

Sandbox validation:
- Execute selected PoCs only in isolated Docker containers.
- Use non-root, no privileged mode, no host mounts, no Docker socket, resource limits, timeouts, and allowlisted network targets.
- Return Confirmed Exploitable, Not Exploitable, or Inconclusive.
- Never interpret timeout or infrastructure failure as Not Exploitable.
- Store execution metadata and evidence.

Evidence:
- Store immutable references to original records, requests, responses, logs, crash traces, PoC hashes, and validation summaries.
- Hash artifacts and redact secrets before display.

Prioritization:
- Use CISA KEV, EPSS, CVSS, asset criticality, internet exposure, validation result, and evidence quality.
- Implement a configurable explainable risk score.
- Assign Immediate, Accelerated, or Standard remediation tiers.
- Store all score inputs and calculation version.

Cases and review:
- Generate analyst-ready cases containing title, summary, technical details, four views, validation, evidence, duplicates, source scanners, CVE/CWE, risk factors, remediation, and review state.
- Analysts can approve, reject, request evidence, change merge decisions, and adjust priority with reasons.
- Final approval/rejection must remain human-controlled.
- Store append-only audit events.

Required architecture:
- Separate parsers, schemas, normalizers, extractors, embedding service, clustering service, sandbox service, evidence repository, risk engine, case service, and review service.
- Use clear type hints, Pydantic models, service boundaries, repository abstraction, tests, and API documentation.
- Return code file by file with setup instructions, environment variables, sample JSON data, database schema, API examples, and test commands.
- Keep the hackathon implementation simple, safe, explainable, and extensible.
```

# 24. Final Product Principle

VulnTriager should automate repetitive analysis while preserving evidence, uncertainty, traceability, and human authority. Its most important behavior is not merely finding similar alerts; it is producing a trustworthy, explainable case that an analyst can verify and act upon.
