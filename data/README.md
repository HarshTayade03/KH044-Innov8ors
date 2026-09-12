# Data

Store project data and data-specific documentation here.

## Corpus overview

Intended corpus: **110 scanner findings + 2 threat-intel feeds + 2 new scanner fixtures**

| File | Scanner | Format | Vuln type | Count |
|---|---|---|---|---|
| `burp_sqli.sarif` | Burp Suite Pro | SARIF 2.1.0 | SQL Injection | 25 |
| `nessus_sqli.json` | Nessus Professional | JSON | SQL Injection | 25 |
| `burp_xss.sarif` | Burp Suite Pro | SARIF 2.1.0 | Cross-Site Scripting | 20 |
| `zap_xss.json` | OWASP ZAP | JSON | Cross-Site Scripting | 20 |
| `burp_ssrf.json` | Burp Suite | JSON | Server-Side Request Forgery | 10 |
| `nessus_ssrf.sarif` | Nessus Professional | SARIF 2.1.0 | Server-Side Request Forgery | 10 |
| `snyk_sca.json` | Snyk | JSON | SCA / Dependency CVEs | 15 |
| `trivy_container.json` | Trivy | JSON | Container / OS CVEs | 15 |

**Total scanner findings: 140**

## Threat intelligence mock feeds

| File | Source | CVEs covered |
|---|---|---|
| `cisa_kev_mock.json` | CISA KEV (mock) | 12 — covers Log4Shell, Spring4Shell, Text4Shell, OpenSSL, HTTP/2 Rapid Reset, and corpus CVEs |
| `epss_mock.json` | EPSS API (mock) | 30 — covers all CVEs present in the full corpus |

## Deduplication test design

Cross-scanner duplicate pairs are deliberately included so the pipeline can validate its deduplication logic:

- **SQLi**: First 5 Nessus SQLi entries match the first 5 Burp SQLi entries (same host + path + parameter).
- **XSS**: First 8 ZAP XSS entries match the first 8 Burp XSS entries (same path + parameter).
- **SSRF**: First 3 Nessus SSRF SARIF entries match the first 3 Burp SSRF entries.
- **CVE overlap**: Log4j CVE-2021-44228 appears in both `snyk_sca.json` and `trivy_container.json` on different targets — should remain **separate** (different container images / packages).

## Scanner data notes

- Burp and ZAP findings contain HTTP request/response evidence with redactable Authorization headers.
- Nessus findings vary in CVSS score completeness (some are `null`) to exercise normalization warnings.
- Snyk findings span multiple package managers: maven, npm, pip, rubygems.
- Trivy findings span multiple container images and both `library` and `os` vulnerability types.
- CISA KEV and EPSS feeds are mock-only; live fetching is deferred per the implementation plan.
