# Supported Scanner Formats

This document describes the input formats accepted by each parser registered in
`src/app/parsers/`. Use it as a reference when preparing sample data or writing
ingestion tests.

The `source_scanner` field in the ingestion API (`POST /api/v1/findings/upload` and
`POST /api/v1/findings`) selects the parser. Valid values are listed in each section.

---

## Contents

- [Nessus / Rapid7 InsightVM](#nessus--rapid7-insightvm)
- [Burp Suite Pro](#burp-suite-pro)
- [OWASP ZAP](#owasp-zap)
- [SARIF 2.1.0 (Generic)](#sarif-210-generic)
- [Snyk SCA](#snyk-sca)
- [Trivy](#trivy)

---

## Nessus / Rapid7 InsightVM

**Parser:** `NessusParser` — `source_scanner = "nessus"`

**Input:** JSON array of finding objects. Rapid7 InsightVM exports can use the same
field names and will be parsed identically.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `plugin_id` | integer | Used as `source_finding_id`; can be `null` |
| `plugin_name` | string | Used as `title`; also used for CWE inference if no explicit CWE |
| `host` | string | Hostname or IP; also accepts `hostname` or `ip` |
| `severity` | string | `"Critical"` / `"High"` / `"Medium"` / `"Low"` / `"Informational"` |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `port` | integer | Port number; coerced to `null` if non-numeric |
| `protocol` | string | e.g. `"tcp"` |
| `cve` | string \| list | Accepts `"CVE-2024-1234"`, `"cve 2024 1234"`, lists — normalised to `CVE-YYYY-NNNNN` |
| `cwe` | string \| integer \| list | Accepts bare integers (`89`), `"CWE-89"`, `"CWE89"` — normalised to `"CWE-89"` |
| `cvss_base_score` | float | Valid range 0–10; values outside range are set to `null` with a warning |
| `cvss3_base_score` | float | Fallback if `cvss_base_score` is absent |
| `description` | string | Also accepts `synopsis` |
| `solution` | string | Remediation advice |
| `plugin_output` | string | Raw scanner output; also accepts `output` |
| `url` | string | Full URL for web findings (preserves cross-scanner dedup context) |
| `path` | string | URL path for web findings |
| `parameter` | string | Vulnerable parameter name |

### Example

```json
{
  "plugin_id": 19001,
  "plugin_name": "SQL Injection in /api/login",
  "host": "app.example.test",
  "port": 443,
  "protocol": "tcp",
  "cve": ["CVE-2024-1001"],
  "cvss_base_score": 8.8,
  "severity": "High",
  "description": "The web application at /api/login is vulnerable to SQL injection.",
  "solution": "Use parameterized SQL queries.",
  "plugin_output": "Detected vulnerable query pattern.",
  "url": "https://app.example.test/api/login",
  "path": "/api/login",
  "parameter": "username"
}
```

---

## Burp Suite Pro

**Parser:** `BurpParser` — `source_scanner = "burp"`

**Input:** JSON array of issue objects exported from Burp Suite Pro. Flat JSON
(not SARIF) is the primary format. SARIF from Burp is handled by the SARIF parser.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `issue_id` | string | Used as `source_finding_id` |
| `name` | string | Vulnerability name; used as `title` |
| `host` | string | Full URL or hostname (e.g. `"https://app.example.test"`) |
| `severity` | string | `"High"` / `"Medium"` / `"Low"` / `"Information"` |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `path` | string | URL path |
| `parameter` | string | Vulnerable parameter |
| `confidence` | string | e.g. `"Certain"` / `"Firm"` / `"Tentative"` |
| `issue_background` | string | Used as `description` |
| `request` | string | Raw HTTP request (may contain `Authorization: Bearer <REDACTED>` after redaction) |
| `response` | string | Raw HTTP response |
| `evidence` | string | Scanner-provided evidence summary |

### Example

```json
{
  "issue_id": "burp-ssrf-001",
  "name": "Server-Side Request Forgery in /api/fetch",
  "host": "https://app.example.test",
  "path": "/api/fetch",
  "parameter": "url",
  "severity": "High",
  "confidence": "Certain",
  "issue_background": "The 'url' parameter allows arbitrary outbound HTTP requests.",
  "request": "POST /api/fetch HTTP/1.1\r\nHost: app.example.test\r\n\r\nurl=http://169.254.169.254/",
  "response": "HTTP/1.1 200 OK\r\n\r\n{\"instance-id\": \"i-0123\"}",
  "evidence": "AWS metadata endpoint returned HTTP 200 with instance credentials."
}
```

---

## OWASP ZAP

**Parser:** `ZAPParser` — `source_scanner = "zap"`

**Input:** JSON array of alert objects from OWASP ZAP's JSON report.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `alert` | string | Alert name; used as `title` |
| `url` | string | Affected URL |
| `riskcode` | string \| integer | `"3"` = High, `"2"` = Medium, `"1"` = Low, `"0"` = Informational |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `alertRef` | string | Used as `source_finding_id` |
| `description` | string | Vulnerability description |
| `param` | string | Vulnerable parameter |
| `attack` | string | Attack payload used |
| `evidence` | string | Evidence string from scanner |
| `solution` | string | Recommended fix |
| `cweid` | string \| integer | CWE ID; coerced to `"CWE-79"` format |
| `confidence` | string | Numeric string `"3"` / `"2"` / `"1"` |

### Example

```json
{
  "alertRef": "ZAP-40012",
  "alert": "Cross Site Scripting (Reflected) at /search",
  "description": "Reflected XSS identified at /search in parameter 'q'.",
  "riskcode": "3",
  "confidence": "3",
  "url": "https://app.example.test/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
  "param": "q",
  "attack": "<svg/onload=alert(1)>",
  "evidence": "<svg/onload=alert(1)>",
  "solution": "Filter and encode all user-supplied input.",
  "cweid": "79"
}
```

---

## SARIF 2.1.0 (Generic)

**Parser:** `GenericSARIFParser` — `source_scanner = "sarif"`

**Input:** SARIF 2.1.0 JSON (`{ "version": "2.1.0", "runs": [...] }`). Used for
Burp Suite Pro SARIF exports, Nessus SARIF exports, and any SARIF-compliant scanner.

### Structure

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": { "name": "Burp Suite Pro", "version": "2024.1.2" }
      },
      "results": [
        {
          "ruleId": "sqli",
          "message": { "text": "SQL Injection detected in /api/login via 'username'." },
          "level": "error",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "https://app.example.test/api/login" },
                "region": { "startLine": 42 }
              }
            }
          ],
          "properties": {
            "host": "https://app.example.test",
            "path": "/api/login",
            "parameter": "username",
            "request": "POST /api/login HTTP/1.1\r\nHost: app.example.test\r\n\r\nusername=' OR '1'='1",
            "response": "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"authenticated\"}",
            "evidence": "Payload changed response structure.",
            "confidence": "Certain",
            "cve_ids": ["CVE-2024-1001"]
          }
        }
      ]
    }
  ]
}
```

### SARIF `level` → severity mapping

| SARIF `level` | Canonical severity |
|---|---|
| `"error"` | `High` |
| `"warning"` | `Medium` |
| `"note"` | `Low` |
| _(absent)_ | `Unknown` |

### SARIF `ruleId` → CWE mapping (Burp rules)

| `ruleId` | CWE |
|---|---|
| `sqli` | `CWE-89` |
| `xss` | `CWE-79` |
| `ssrf` | `CWE-918` |
| `CWE-80` and other child CWEs | Resolved via `CWE_PARENT_MAP` in `parsers/base.py` |

---

## Snyk SCA

**Parser:** `SnykParser` — `source_scanner = "snyk"`

**Input:** JSON array of vulnerability objects from `snyk test --json`.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Snyk vulnerability ID; used as `source_finding_id` |
| `package_name` | string | Also accepts `pkgName` or `packageName` |
| `severity` | string | `"Critical"` / `"High"` / `"Medium"` / `"Low"` |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `package_version` | string | Installed version; also accepts `version` |
| `fixed_in` | list\[string\] | Fixed version(s) |
| `cve` | string \| list | CVE identifier(s) |
| `cwe` | string \| list | CWE identifier(s) |
| `cvss_score` | float | Also accepts `cvssScore` |
| `title` | string | Vulnerability title |
| `description` | string | Detailed description |
| `file` | string | Manifest file (e.g. `pom.xml`, `package.json`) |
| `package_manager` | string | e.g. `"maven"`, `"npm"`, `"pip"`, `"rubygems"` |
| `from` | list\[string\] | Dependency chain |
| `identifiers` | object | Alternative CVE/CWE source; `{ "CVE": [...], "CWE": [...] }` |

### Example

```json
{
  "id": "SNYK-JAVA-LOG4J-2314720",
  "package_name": "log4j-core",
  "package_version": "2.14.1",
  "fixed_in": ["2.17.1"],
  "cve": "CVE-2021-44228",
  "cwe": ["CWE-502"],
  "severity": "Critical",
  "cvss_score": 10.0,
  "title": "Remote Code Execution (Log4Shell)",
  "file": "pom.xml",
  "description": "Apache Log4j2 allows RCE via JNDI lookup when attacker-controlled data is logged.",
  "package_manager": "maven",
  "from": ["log4j-core@2.14.1"]
}
```

---

## Trivy

**Parser:** `TrivyParser` — `source_scanner = "trivy"`

**Input:** JSON array of vulnerability objects from `trivy image --format json`. Both
snake_case (CLI output) and PascalCase (Trivy JSON v2) field names are accepted.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `vulnerability_id` | string | CVE or GHSA ID; also accepts `VulnerabilityID` |
| `pkg_name` | string | Package name; also accepts `PkgName` |
| `severity` | string | `"CRITICAL"` / `"HIGH"` / `"MEDIUM"` / `"LOW"` / `"UNKNOWN"`; also accepts `Severity` |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `target` | string | Container image or file target (e.g. `"auth-service:2.1.0"`); also accepts `Target` |
| `type` | string | `"os"` or `"library"`; also accepts `Type` |
| `installed_version` | string | Also accepts `InstalledVersion` |
| `fixed_version` | string | Also accepts `FixedVersion` |
| `title` | string | Short vulnerability title; also accepts `Title` |
| `description` | string | Full description; also accepts `Description` |
| `cvss_score` | float | Also accepts nested `CVSS.nvd.V3Score` |
| `cwe_ids` | list\[string\] | Also accepts `CweIDs` |
| `primary_url` | string | NVD or advisory link; also accepts `PrimaryURL` |

### Example

```json
{
  "target": "api-gateway:1.5.3",
  "type": "library",
  "vulnerability_id": "CVE-2021-44228",
  "pkg_name": "log4j",
  "installed_version": "2.14.1",
  "fixed_version": "2.17.1",
  "severity": "Critical",
  "title": "Log4Shell Remote Code Execution via JNDI Lookup",
  "description": "Apache Log4j2 JNDI features allow RCE via attacker-controlled LDAP endpoints.",
  "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  "cwe_ids": ["CWE-502"]
}
```

---

## Normalisation rules (all parsers)

The `NormalizerService` applies these rules after every parser runs:

| Field | Rule |
|---|---|
| CVE IDs | `"cve 2024 1234"`, `"CVE_2024_1234"`, CVE URLs → `"CVE-2024-1234"`. Invalid patterns are dropped. |
| CWE IDs | `89`, `"CWE89"`, `"cwe-89"` → `"CWE-89"`. Child CWEs resolve to root via `CWE_PARENT_MAP`. |
| Severity | `"URGENT"`, `"SEVERE"` and other non-canonical values → `"Unknown"` with a warning. |
| CVSS | Values outside 0–10 → `null` with a warning. Non-numeric strings → `null` with a warning. |
| Port | Non-integer strings → `null` with a warning. |
| Completeness | Fraction of 7 required fields present (0.0–1.0). Findings below threshold get `normalized_with_warnings`. |

See `src/app/parsers/base.py` for the normalization function implementations.
