# Module 1 — Parsers, Normalizer & Ingestion

**Task IDs**: M1-01 through M1-14
**Estimated Time**: 90 minutes
**Depends on**: Module 0 complete and verified
**Produces**: Populated `scanner_findings` and `normalized_findings` tables from file upload, direct POST, or manual entry

---

## Purpose

Module 1 is the **entry point of the entire pipeline**. It receives raw, messy, scanner-specific vulnerability data and converts it into the unified canonical schema that every downstream module reads from.

After this module, no downstream code ever needs to know what scanner a finding came from. The canonical schema hides all scanner-specific differences.

---

## Input Formats This Module Must Handle

### Format 1: SARIF 2.1.0 (Static Analysis Results Interchange Format)

SARIF is a JSON format standardized by OASIS. Our synthetic data uses it for Burp Suite and Nessus SARIF output.

**SARIF top-level structure**:
```
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "...", "version": "...", "rules": [...] } },
      "results": [
        {
          "ruleId": "...",         ← vulnerability identifier / CWE rule
          "message": { "text": "..." },
          "level": "error"|"warning"|"note"|"none",  ← severity
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "..." },  ← file path or URL
                "region": { "startLine": N }
              }
            }
          ],
          "properties": { ... }   ← scanner-specific extra data
        }
      ]
    }
  ]
}
```

**What the SARIF parser must extract**:
- `runs[0].tool.driver.name` → `source.tool_name`
- `runs[0].tool.driver.version` → `source.tool_version`
- `result.ruleId` → map to CWE (see CWE mapping table below). If ruleId looks like `CWE-89` directly, use it. If it looks like `burp-sqli`, look up in TOOL_RULE_TO_CWE dict.
- `result.message.text` → `vulnerability.description`
- `result.level` → map to severity: `error→High`, `warning→Medium`, `note→Low`, `none→Informational`
- `result.locations[0].physicalLocation.artifactLocation.uri` → `location.url` or `location.file`
- `result.locations[0].physicalLocation.region.startLine` → `location.line_number` (store in metadata)
- `result.properties` → scanner-specific; check for `request`, `response`, `payload`, `confidence` keys

**Burp SARIF specifics** (our primary SARIF source):
- `ruleId` will be strings like `sqli`, `xss`, `ssrf` — map via `BURP_RULE_TO_CWE` dict
- `properties.request` → `evidence.request`
- `properties.response` → `evidence.response`
- `properties.confidence` → `source.original_confidence`
- `properties.host` → `location.host`
- `properties.path` → `location.path`
- `properties.parameter` → `location.parameter`

---

### Format 2: Nessus JSON

Nessus exports findings as a JSON array of plugin result objects.

**Example single record**:
```
{
  "plugin_id": "19506",
  "plugin_name": "Apache HTTP Server Vulnerability",
  "host": "10.0.0.15",
  "port": 443,
  "protocol": "tcp",
  "cve": ["CVE-2024-1234"],        ← may be string or list
  "cvss_base_score": 8.8,
  "severity": "High",              ← "Critical"/"High"/"Medium"/"Low"/"None"
  "description": "...",
  "solution": "...",
  "plugin_output": "..."           ← raw scanner output text
}
```

**What the Nessus parser must extract and where it goes**:
- `plugin_name` → `vulnerability.title`
- `description` → `vulnerability.description`
- `cve` (normalize if string; may be "CVE-2024-1234" or ["CVE-2024-1234"]) → `vulnerability.cve_ids`
- `cvss_base_score` → `vulnerability.cvss_score`
- `severity` → `source.original_severity_raw`; also map directly to `vulnerability.severity`
- `host` → `location.host`
- `port` → `location.port` (integer)
- `protocol` → `location.protocol`
- `solution` → `remediation.recommendation`
- `plugin_output` → `evidence.raw_output`
- `plugin_id` → use as `source_finding_id`

**CWE inference for Nessus**: Nessus does not typically provide CWE IDs. Use the `NESSUS_PLUGIN_TO_CWE` lookup dict keyed by `plugin_name` substring matching. Example entries: `"sql injection" → CWE-89`, `"cross-site scripting" → CWE-79`, `"server-side request forgery" → CWE-918`. If no match, leave `cwe_ids` empty with a warning.

---

### Format 3: OWASP ZAP JSON

ZAP exports a flat JSON format.

**Example record**:
```
{
  "alertRef": "40012",
  "alert": "Cross Site Scripting (Reflected)",
  "description": "...",
  "riskcode": "3",                 ← 3=High, 2=Medium, 1=Low, 0=Informational
  "confidence": "2",               ← 3=High, 2=Medium, 1=Low
  "url": "https://app.example.test/search?q=test",
  "param": "q",
  "attack": "<script>alert(1)</script>",
  "evidence": "...",
  "solution": "...",
  "reference": "...",
  "cweid": "79",                   ← CWE number without prefix
  "wascid": "8"
}
```

**Extraction rules**:
- `alert` → `vulnerability.title`
- `description` → `vulnerability.description`
- `riskcode` → map `3→High, 2→Medium, 1→Low, 0→Informational` → `vulnerability.severity`
- `url` → `location.url`, parse to extract `host`, `path`, `port`, `protocol`
- `param` → `location.parameter`
- `attack` → `evidence.payload`
- `evidence` → `evidence.summary`
- `solution` → `remediation.recommendation`
- `cweid` → normalize to `CWE-{cweid}` → `vulnerability.cwe_ids`
- `confidence` → map `3→Certain, 2→Firm, 1→Tentative` → `source.original_confidence`

> **Note**: ZAP is currently in scope as a data source for XSS findings. The parser should be named `ZAPParser` and registered in the PARSER_REGISTRY as `"zap"`.

---

### Format 4: Manual Entry Form

The analyst dashboard has a form where someone can enter a finding by hand. This is the simplest format — it posts a structured JSON body directly matching a subset of the canonical schema.

**Required fields for manual entry**:
- `title` (string)
- `description` (string)
- `scanner_name` (string — free text, e.g. "Manual Review")
- `severity` (one of: Critical / High / Medium / Low / Informational / Unknown)
- `asset_name` (string)

**Optional fields**:
- `cve_ids` (list of strings)
- `cwe_ids` (list of strings)
- `url` (string)
- `parameter` (string)
- `cvss_score` (float)
- `request` (string)
- `response` (string)
- `notes` (string → goes into `evidence.summary`)

The manual entry API endpoint (`POST /api/v1/findings/manual`) must accept this payload, create a scanner_findings record with `source_scanner = "manual"`, then run it through the same normalizer as every other finding.

---

## The Canonical Finding Schema (What Every Parser Must Produce)

Every parser converts its raw format into an intermediate dict, and then the normalizer converts that dict into a fully validated `NormalizedFinding` object.

The canonical schema has these top-level sections:

### `identity` block
- `finding_id`: UUID string, generated by the system (not from the scanner)
- `fingerprint`: SHA-256 string, computed deterministically from `cwe_primary + canonical_path + parameter_class`
- `source_scanner`: normalized scanner name string (nessus / burp / zap / snyk / trivy / sarif / manual)
- `source_finding_id`: the scanner's own ID for this finding (nullable)
- `ingestion_batch_id`: UUID of the upload batch this finding arrived in
- `ingested_at`: ISO 8601 datetime string

### `vulnerability` block
- `title`: human-readable vulnerability name (required, never null)
- `description`: detailed description (nullable)
- `cve_ids`: list of normalized CVE strings, e.g. `["CVE-2024-1234"]` (may be empty)
- `cwe_ids`: list of normalized CWE strings, e.g. `["CWE-89"]` (may be empty)
- `cwe_primary`: single CWE for fingerprinting; first item of cwe_ids, resolved to root via hierarchy if needed (nullable)
- `severity`: one of `Critical / High / Medium / Low / Informational / Unknown` (required, use `Unknown` if not determinable)
- `cvss_score`: float 0.0–10.0 (nullable — absence is not the same as 0)
- `cvss_vector`: CVSS vector string (nullable)
- `cvss_version`: `"3.0"`, `"3.1"`, or `"4.0"` (nullable)
- `severity_source`: one of `tool / derived / analyst_override`
- `severity_confidence`: float 0.0–1.0 (1.0 if scanner provided CVSS; lower if derived from qualitative mapping)

### `asset` block
- `asset_name`: hostname, container image, or package name (required)
- `asset_type`: `web_application / api / host / container / library / unknown`
- `environment`: `prod / staging / dev / lab / unknown` (default to `lab` for synthetic data)
- `internet_facing`: boolean (default `false` unless clearly indicated)
- `criticality`: `critical / high / medium / low / unknown` (nullable)

### `location` block
- `host`: hostname or IP (nullable)
- `port`: integer (nullable)
- `protocol`: `http / https / tcp / udp` (nullable)
- `url`: full URL string (nullable)
- `path`: URL path without query string, e.g. `/api/login` (nullable)
- `parameter`: the vulnerable parameter name, e.g. `username` (nullable — critical for dedup)
- `parameter_class`: one of `id / auth / redirect / file / generic` — inferred from parameter name patterns (nullable)
- `file`: source code file path (nullable — used for SAST findings)
- `package`: package name (nullable — used for SCA findings)
- `installed_version`: package version (nullable)
- `fixed_version`: version that fixes the vulnerability (nullable)
- `container_image`: Docker image tag (nullable)

### `evidence` block
- `summary`: human-readable description of the evidence (nullable)
- `request`: HTTP request string (nullable)
- `response`: HTTP response string (nullable)
- `payload`: the attack payload string (nullable)
- `raw_output`: scanner's raw output text (nullable)
- `code_snippet`: relevant code (nullable — for SAST findings)

### `remediation` block
- `recommendation`: fix guidance text (nullable)
- `fixed_version`: version to upgrade to (nullable)
- `reference_urls`: list of URL strings (may be empty)

### `provenance` block
- `source_file`: name of the uploaded file (nullable)
- `parser_name`: name of the parser class used (e.g. `NessusParser`)
- `parser_version`: parser version string (e.g. `1.0.0`)
- `raw_record_hash`: SHA-256 of the original raw JSON record
- `original_data`: the complete original raw record stored as-is

### `quality` block
- `normalization_status`: `normalized / normalized_with_warnings / rejected`
- `completeness_score`: float 0.0–1.0, fraction of required fields that are populated
- `warnings`: list of string messages describing non-fatal issues
- `errors`: list of string messages for fatal issues (if any errors → status = rejected)

---

## Normalization Utility Functions

These pure functions must live in `services/normalizer.py` and be individually testable. They are called by the normalizer after parsing.

### `normalize_cve(raw: str) -> str | None`
- Accepts any CVE-like string: `"cve-2024-1234"`, `"CVE 2024 1234"`, `"CVE_2024_1234"`, `"https://cve.org/CVE-2024-1234"`
- Strip any URL prefix, replace spaces/underscores with hyphens, uppercase
- Output: `"CVE-2024-1234"` or `None` if it cannot be made to match `CVE-\d{4}-\d{4,}`
- Log a warning if input was non-null but output is None

### `normalize_cwe(raw: str | int) -> str | None`
- Accepts: `89`, `"89"`, `"CWE89"`, `"cwe-89"`, `"CWE 89"`, `"CWE-0089"`
- Output: `"CWE-89"` (no leading zeros, uppercase)
- Return None if not parseable as an integer

### `normalize_severity(raw: str) -> tuple[str, str]`
- Returns `(canonical_severity, source_type)`
- Input may be: qualitative label OR a number (treat as CVSS score)
- Mapping:
  - `critical / CRITICAL / 9.0-10.0` → `("Critical", "tool")`
  - `high / HIGH / error / 7.0-8.9` → `("High", "tool")`
  - `medium / MEDIUM / warning / 4.0-6.9` → `("Medium", "tool")`
  - `low / LOW / note / 0.1-3.9` → `("Low", "tool")`
  - `info / informational / none / 0.0` → `("Informational", "tool")`
  - `3` (ZAP riskcode) → see ZAP mapping above
  - anything unrecognized → `("Unknown", "tool")` with a warning

### `derive_cvss_from_severity(severity: str) -> tuple[float, float]`
- Used when scanner provides qualitative severity but no CVSS score
- Returns `(midpoint_score, confidence)`:
  - `Critical → (9.5, 0.5)`, `High → (7.5, 0.5)`, `Medium → (5.0, 0.5)`, `Low → (2.0, 0.5)`, `Informational → (0.0, 0.3)`
- Caller must set `severity_source = "derived"` and use the returned confidence value

### `compute_fingerprint(cwe_primary: str | None, url_path: str | None, parameter_class: str | None) -> str`
- `cwe_primary`: resolved CWE (root of hierarchy), or the string `"NO_CWE"` if None
- `url_path`: canonicalize by collapsing numeric path segments (`/user/123/posts` → `/user/{id}/posts`). Use `"NO_PATH"` if None.
- `parameter_class`: one of the 5 classes or `"NO_PARAM"` if None
- Compute: `hashlib.sha256(f"{cwe_primary}|{canonical_path}|{parameter_class}".encode()).hexdigest()`
- This must be deterministic: same inputs always produce the same fingerprint across runs, machines, and Python versions

### `infer_parameter_class(param_name: str | None) -> str | None`
- Maps parameter name patterns to classes:
  - `id / user_id / product_id / uid` → `"id"`
  - `token / password / key / auth / apikey / session` → `"auth"`
  - `url / redirect / return / next / callback` → `"redirect"`
  - `file / path / filename / upload / attachment` → `"file"`
  - anything else (non-null) → `"generic"`
  - None → `None`

### `compute_completeness(finding: dict) -> float`
- Count how many of these 7 required fields are non-null and non-empty:
  1. `vulnerability.title`
  2. `vulnerability.severity` (not "Unknown")
  3. `asset.asset_name`
  4. `location` (at least one of: host, url, path, package, file)
  5. `evidence` (at least one of: summary, request, raw_output)
  6. `provenance.raw_record_hash`
  7. `vulnerability.cwe_ids` OR `vulnerability.cve_ids` (at least one present)
- Return `count / 7` as a float

---

## CWE Mapping Dictionaries

These must be maintained as static dicts in `parsers/base.py` so all parsers can import them.

### `BURP_RULE_TO_CWE`
```
"sqli" → "CWE-89"
"xss" → "CWE-79"
"ssrf" → "CWE-918"
"idor" → "CWE-639"
"csrf" → "CWE-352"
"xxe" → "CWE-611"
"path-traversal" → "CWE-22"
"open-redirect" → "CWE-601"
"rce" → "CWE-78"
"info-disclosure" → "CWE-200"
"broken-auth" → "CWE-287"
```

### `NESSUS_PLUGIN_TO_CWE` (substring match on plugin_name, lowercase)
```
"sql injection" → "CWE-89"
"cross-site scripting" → "CWE-79"
"xss" → "CWE-79"
"server-side request forgery" → "CWE-918"
"ssrf" → "CWE-918"
"path traversal" → "CWE-22"
"directory traversal" → "CWE-22"
"remote code execution" → "CWE-78"
"command injection" → "CWE-77"
"authentication bypass" → "CWE-287"
"ssl" → "CWE-326"
"tls" → "CWE-326"
"csrf" → "CWE-352"
"information disclosure" → "CWE-200"
```

### `CWE_PARENT_MAP` (for hierarchy resolution in deduplication — defined here for reference)
```
"CWE-564" → "CWE-89"   (Hibernate SQL injection is a child of SQL injection)
"CWE-80"  → "CWE-79"   (Basic XSS variant)
"CWE-81"  → "CWE-79"   (Improper Neutralization in error message → XSS)
"CWE-85"  → "CWE-79"   (Doubled Character XSS → XSS)
"CWE-86"  → "CWE-79"   (Improper Neutralization of invalid characters → XSS)
"CWE-87"  → "CWE-79"   (Alternate XSS Syntax → XSS)
"CWE-918" → "CWE-918"  (SSRF has no parent in our current scope — is root)
"CWE-639" → "CWE-285"  (IDOR is a child of Improper Authorization)
```
This dict is used by the deduplication module (Module 3). Define it here so parsers can also use it for CWE normalization.

---

## Synthetic Data Specification

The following files in `data/` must be created. They do not need to be realistic from a scanner output standpoint — they need to be correctly formatted so the parsers handle them correctly and the edge cases exercise the deduplication logic.

### `data/burp_sqli.sarif` — 25 SQLi findings in SARIF format

Content rules:
- All 25 findings must have `ruleId: "sqli"` (maps to CWE-89)
- Endpoints must include varied paths: `/api/login`, `/api/user`, `/api/search`, `/api/order`, `/api/product`, etc.
- Parameters must vary: `username`, `id`, `q`, `order_id`, `category` — each on a different endpoint
- `level` should vary: 15 as `error` (High), 8 as `warning` (Medium), 2 as `note` (Low)
- 5 of the 25 must be EXACT duplicates of findings in `data/nessus_sqli.json` (same endpoint + same parameter) — these test cross-scanner dedup
- 2 findings must be on the same path (`/api/user`) but different parameters (`id` vs `name`) — these must NOT be deduped
- Include `request` and `response` in the `properties` block for at least 15 findings

### `data/nessus_sqli.json` — 25 SQLi findings in Nessus JSON format

Content rules:
- All 25 must have `plugin_name` containing "SQL Injection" (for CWE inference)
- Must have 5 findings with the exact same `host + path + parameter` values as 5 of the Burp SARIF findings (cross-scanner dups)
- 8 findings must have no `cvss_base_score` (only qualitative `severity`) — tests derived CVSS
- 3 findings must have no `cve` field at all — tests null CVE handling
- Severity distribution: 10 High, 10 Medium, 5 Low

### `data/burp_xss.sarif` — 20 XSS findings in SARIF format

Content rules:
- Mix of `ruleId: "xss"` (CWE-79) — 14 findings
- 6 findings with `ruleId: "xss"` but with CWE hint `CWE-80` in properties (child CWE test)
- Endpoints: `/search`, `/comments`, `/profile`, `/feedback`, `/review`, etc.
- 8 findings must match endpoints in `data/zap_xss.json` (cross-scanner dups)
- Include `attack` (payload) in properties for at least 15 findings

### `data/zap_xss.json` — 20 XSS findings in OWASP ZAP JSON format

Content rules:
- All must have `cweid: "79"` and `alert` containing "Cross Site Scripting"
- 8 must be exact endpoint+parameter duplicates of Burp XSS findings
- `riskcode` distribution: 5 with code `3` (High), 10 with code `2` (Medium), 5 with code `1` (Low)
- All must have the `attack` field with an actual XSS payload string

### `data/burp_ssrf.json` — 10 SSRF findings in Burp JSON (not SARIF, flat JSON)

Burp flat JSON format (not SARIF):
```
{
  "issue_id": "burp-ssrf-001",
  "name": "Server-Side Request Forgery",
  "host": "https://app.example.test",
  "path": "/api/fetch",
  "parameter": "url",
  "severity": "High",
  "confidence": "Certain",
  "issue_background": "The url parameter is vulnerable to SSRF...",
  "request": "POST /api/fetch url=http://internal.service/admin",
  "response": "HTTP/1.1 200 OK {internal service response}",
  "evidence": "Internal service response received."
}
```
- All 10 must use CWE-918 (via BURP_RULE_TO_CWE lookup on `"ssrf"`)
- Use varied `path` and `parameter` values
- 3 must be endpoint+parameter duplicates of findings in `data/nessus_ssrf.sarif`

### `data/nessus_ssrf.sarif` — 10 SSRF findings in Nessus SARIF format

- Use `ruleId: "ssrf"` or a rule with `tags: ["CWE-918"]` in the SARIF rules section
- 3 must match Burp SSRF findings exactly (cross-scanner dups)

### `data/cisa_kev_mock.json`

Format must match the real CISA KEV API response:
```json
{
  "title": "CISA Known Exploited Vulnerabilities Catalog",
  "catalogVersion": "2024.01.01",
  "dateReleased": "2024-01-01",
  "count": 5,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "...",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known"
    }
    // ... more entries including CVEs that appear in the synthetic SQLi/XSS/SSRF data
  ]
}
```
Include at least 3 CVEs that actually appear in the synthetic dataset so KEV enrichment has visible effect on risk scoring.

### `data/epss_mock.json`

Format must match the FIRST.org EPSS API response structure:
```json
{
  "status": "OK",
  "status-code": 200,
  "version": "1.0",
  "access": "public",
  "total": 3,
  "offset": 0,
  "limit": 100,
  "data": [
    { "cve": "CVE-2021-44228", "epss": "0.9750", "percentile": "0.9995", "date": "2024-01-01" },
    { "cve": "CVE-2024-1234", "epss": "0.0234", "percentile": "0.7234", "date": "2024-01-01" }
  ]
}
```
Include EPSS scores for every CVE used in the synthetic dataset.

---

## Ingestion API Contracts

### `POST /api/v1/findings/upload`
- Accept: `multipart/form-data`
- Form fields: `file` (the JSON or SARIF file), `source_scanner` (one of: `nessus / burp / zap / snyk / trivy / sarif / manual`)
- Read the file bytes, parse as JSON, detect if top-level is a list (batch) or object (single record or SARIF with `runs` key)
- If SARIF (has `runs` key): extract all results from all runs
- Pass to the appropriate parser from PARSER_REGISTRY
- Run normalizer on each result
- Save to DB (both scanner_findings and normalized_findings)
- Return: `BatchSummary` (see schema below)

### `POST /api/v1/findings`
- Accept: `application/json`
- Body: `{ "source_scanner": "nessus", "findings": [ {...}, {...} ] }`
- Same processing pipeline as upload endpoint
- Return: `BatchSummary`

### `POST /api/v1/findings/manual`
- Accept: `application/json`
- Body: the manual entry fields (see Format 4 above)
- Validates required fields (title, severity, asset_name)
- Creates a minimal but complete NormalizedFinding
- Returns: `{ "finding_id": "...", "status": "normalized" }`

### BatchSummary response shape:
```
{
  "batch_id": "uuid string",
  "source_scanner": "nessus",
  "total_received": 25,
  "normalized": 20,
  "normalized_with_warnings": 4,
  "rejected": 1,
  "rejected_details": [ { "index": 3, "reason": "Missing required field: title" } ],
  "status": "completed",
  "next_stage": "multi_view_extraction"
}
```

---

## Error Handling Rules for Parsers and Normalizer

- **One bad record must not stop a batch.** If record #3 fails to parse, records 1, 2, 4, 5... must still be processed.
- **Track each failure.** Add a `rejected_details` entry for each failed record with its index and the reason.
- **Do not invent missing data.** If a field is missing, leave it null. Do not guess or default to a placeholder string.
- **Preserve the original.** Even for a rejected record, write the raw data and its hash to `scanner_findings` with `status = "rejected"`. The data is never thrown away.
- **Warn, don't reject, for recoverable issues**: missing CVSS (warn + derive), missing CWE (warn + leave null), inconsistent severity (warn + use the value anyway), extra unknown fields in input (warn + ignore them).
- **Reject only for fatal issues**: record is not valid JSON, required field `title` is completely absent and cannot be inferred from any other field, data type is fundamentally wrong (e.g. severity is a nested object with no parseable value).

---

## Testing Targets for Module 1

An agent implementing tests for this module must write tests covering these exact scenarios:

| Test Name | What It Verifies |
|---|---|
| `test_burp_sarif_sqli_parse` | Burp SARIF result with `ruleId="sqli"` → `cwe_ids=["CWE-89"]`, location fields populated |
| `test_nessus_json_sqli_parse` | Nessus finding with CWE inferred from plugin_name |
| `test_zap_xss_parse` | ZAP JSON XSS finding → `cwe_ids=["CWE-79"]`, `severity="High"` (riskcode 3) |
| `test_nessus_missing_cvss_derives_score` | Nessus High severity with no CVSS → `cvss_score=7.5`, `severity_source="derived"`, `severity_confidence=0.5` |
| `test_normalize_cve_variants` | `"cve-2024-1234"`, `"CVE 2024-1234"`, `"CVE_2024_1234"` all → `"CVE-2024-1234"` |
| `test_normalize_cwe_variants` | `"89"`, `"CWE89"`, `"cwe-89"`, `89` all → `"CWE-89"` |
| `test_fingerprint_same_inputs` | Two findings with same CWE + path + param_class → identical fingerprints |
| `test_fingerprint_diff_param` | `/api/user` with param `id` vs param `name` → different fingerprints |
| `test_batch_one_bad_record` | Batch of 5 with record #3 missing title → 4 normalized, 1 rejected, batch continues |
| `test_manual_entry_api` | POST to `/findings/manual` with minimum fields → returns finding_id, status=normalized |
| `test_completeness_score_full` | Finding with all 7 required fields → `completeness_score = 1.0` |
| `test_completeness_score_partial` | Finding missing cve/cwe and evidence → `completeness_score < 0.6` |

---

## Verification (How to Know Module 1 Is Done)

1. Run `pytest tests/test_parsers.py tests/test_normalizer.py -v` — all tests pass.
2. Upload `data/burp_sqli.sarif` via `POST /api/v1/findings/upload?source_scanner=burp` and get a valid `BatchSummary` with `normalized >= 23`.
3. Check the SQLite DB: `SELECT COUNT(*) FROM normalized_findings` returns 25 (or close to it depending on edge cases).
4. Retrieve a single finding: `GET /api/v1/findings/{finding_id}` returns the full canonical JSON.
5. Check that findings with no CVE have `cve_ids = []` (not null, not missing key).
6. Check that the raw record is preserved in `scanner_findings.raw_data`.
