"""
scratch/generate_datasets.py — Generator for synthetic vulnerability findings.

Generates 110 total findings across 6 dataset files:
- 50 SQLi (25 Burp SARIF, 25 Nessus JSON)
- 40 XSS (20 Burp SARIF, 20 OWASP ZAP JSON)
- 20 SSRF (10 Burp JSON, 10 Nessus SARIF)
- CISA KEV Mock catalog
- EPSS Mock data
"""

import json
import os

DATA_DIR = r"c:\Users\harsh\Downloads\innov8ors\data"
os.makedirs(DATA_DIR, exist_ok=True)

# ── 1. Burp SQLi SARIF (25 findings) ──────────────────────────────────────────
burp_sqli_results = []
endpoints_sqli = [
    ("/api/login", "username"),
    ("/api/user", "id"),
    ("/api/search", "q"),
    ("/api/order", "order_id"),
    ("/api/product", "category"),
    ("/api/profile", "user_id"),
    ("/api/account", "acc_num"),
    ("/api/billing", "invoice_id"),
    ("/api/cart", "item_id"),
    ("/api/checkout", "coupon"),
    ("/api/admin/user", "uid"),
    ("/api/report", "start_date"),
    ("/api/analytics", "metric"),
    ("/api/export", "format"),
    ("/api/comments", "post_id"),
    ("/api/feedback", "subject"),
    ("/api/notifications", "filter"),
    ("/api/settings", "theme"),
    ("/api/logs", "level"),
    ("/api/audit", "actor"),
    ("/api/roles", "role_id"),
    ("/api/permissions", "perm_id"),
    ("/api/tokens", "token_id"),
    ("/api/sessions", "session_id"),
    ("/api/user", "name"), # Endpoint same as #2, but param differs (id vs name) -> MUST STAY SEPARATE
]

for idx, (path, param) in enumerate(endpoints_sqli, start=1):
    level = "error" if idx <= 15 else ("warning" if idx <= 23 else "note")
    cve = f"CVE-2024-{1000 + idx}" if idx <= 10 else None
    burp_sqli_results.append({
        "ruleId": "sqli",
        "message": {"text": f"SQL Injection detected in endpoint {path} via parameter '{param}'."},
        "level": level,
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f"https://app.example.test{path}"},
                "region": {"startLine": 42 + idx}
            }
        }],
        "properties": {
            "host": "https://app.example.test",
            "path": path,
            "parameter": param,
            "request": f"POST {path} HTTP/1.1\r\nHost: app.example.test\r\nAuthorization: Bearer secret_token_xyz{idx}\r\n\r\n{param}=' OR '1'='1",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"authenticated\",\"user\":\"admin\"}",
            "evidence": f"Payload changed response structure on parameter {param}.",
            "confidence": "Certain",
            "cve_ids": [cve] if cve else []
        }
    })

burp_sqli_sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "Burp Suite Pro", "version": "2024.1.2"}},
        "results": burp_sqli_results
    }]
}

with open(os.path.join(DATA_DIR, "burp_sqli.sarif"), "w") as f:
    json.dump(burp_sqli_sarif, f, indent=2)


# ── 2. Nessus SQLi JSON (25 findings) ──────────────────────────────────────────
nessus_sqli_list = []
for idx in range(1, 26):
    # First 5 correspond to exact endpoint+param of burp_sqli for cross-scanner dedup test
    path, param = endpoints_sqli[idx - 1] if idx <= 5 else (f"/api/nessus_v{idx}", f"param_{idx}")
    cve = f"CVE-2024-{1000 + idx}" if idx <= 10 else None
    cvss = 8.8 if idx <= 15 else (5.5 if idx <= 22 else None)  # 3 missing CVSS score

    nessus_sqli_list.append({
        "plugin_id": 19000 + idx,
        "plugin_name": f"Apache HTTP / Backend SQL Injection in {path}",
        "host": "app.example.test" if idx <= 5 else f"10.0.0.{10 + idx}",
        "port": 443,
        "protocol": "tcp",
        "cve": [cve] if cve else [],
        "cvss_base_score": cvss,
        "severity": "High" if idx <= 15 else "Medium",
        "description": f"The installed web application at {path} is vulnerable to SQL injection via parameter '{param}'.",
        "solution": "Use parameterized SQL queries and input validation.",
        "plugin_output": f"Detected vulnerable query pattern at path {path} with parameter {param}."
    })

with open(os.path.join(DATA_DIR, "nessus_sqli.json"), "w") as f:
    json.dump(nessus_sqli_list, f, indent=2)


# ── 3. Burp XSS SARIF (20 findings) ────────────────────────────────────────────
burp_xss_results = []
endpoints_xss = [
    ("/search", "q"),
    ("/comments", "text"),
    ("/profile/edit", "bio"),
    ("/feedback", "message"),
    ("/review/submit", "comment"),
    ("/contact", "body"),
    ("/forum/post", "content"),
    ("/chat/send", "msg"),
    ("/user/status", "status_text"),
    ("/survey/answer", "ans1"),
    ("/blog/comment", "remark"),
    ("/support/ticket", "description"),
    ("/mail/compose", "body"),
    ("/notes/create", "title"),
    ("/tags/add", "tag_name"),
    ("/items/search", "query"),
    ("/custom/field", "val"),
    ("/widget/config", "label"),
    ("/theme/custom", "css_code"),
    ("/page/builder", "html_snippet"),
]

for idx, (path, param) in enumerate(endpoints_xss, start=1):
    rule_id = "xss" if idx <= 14 else "CWE-80" # child CWE variant test
    cve = f"CVE-2024-200{idx}" if idx <= 5 else None
    burp_xss_results.append({
        "ruleId": rule_id,
        "message": {"text": f"Reflected Cross-Site Scripting (XSS) in {path} parameter '{param}'."},
        "level": "error" if idx <= 12 else "warning",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f"https://app.example.test{path}"},
                "region": {"startLine": 10 + idx}
            }
        }],
        "properties": {
            "host": "https://app.example.test",
            "path": path,
            "parameter": param,
            "request": f"GET {path}?{param}=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: app.example.test",
            "response": f"HTTP/1.1 200 OK\r\n\r\n<html><body><script>alert(1)</script></body></html>",
            "evidence": f"Reflected unescaped payload in response body for parameter {param}.",
            "confidence": "Certain",
            "cve_ids": [cve] if cve else []
        }
    })

burp_xss_sarif = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Burp Suite Pro", "version": "2024.1.2"}},
        "results": burp_xss_results
    }]
}

with open(os.path.join(DATA_DIR, "burp_xss.sarif"), "w") as f:
    json.dump(burp_xss_sarif, f, indent=2)


# ── 4. OWASP ZAP XSS JSON (20 findings) ────────────────────────────────────────
zap_xss_list = []
for idx in range(1, 21):
    # First 8 match burp_xss endpoints for cross-scanner dedup test
    path, param = endpoints_xss[idx - 1] if idx <= 8 else (f"/zap_page_{idx}", f"zap_param_{idx}")
    zap_xss_list.append({
        "alertRef": f"ZAP-400{idx}",
        "alert": f"Cross Site Scripting (Reflected) at {path}",
        "description": f"A reflected XSS vulnerability was identified at {path} in parameter '{param}'.",
        "riskcode": "3" if idx <= 12 else "2",
        "confidence": "3",
        "url": f"https://app.example.test{path}?{param}=%3Csvg%2Fonload%3Dalert(1)%3E",
        "param": param,
        "attack": "<svg/onload=alert(1)>",
        "evidence": "<svg/onload=alert(1)>",
        "solution": "Filter and encode all user-supplied input before rendering.",
        "cweid": "79"
    })

with open(os.path.join(DATA_DIR, "zap_xss.json"), "w") as f:
    json.dump(zap_xss_list, f, indent=2)


# ── 5. Burp SSRF JSON (10 findings) ───────────────────────────────────────────
burp_ssrf_list = []
endpoints_ssrf = [
    ("/api/fetch", "url"),
    ("/api/webhook", "target"),
    ("/api/proxy", "dest"),
    ("/api/import", "file_url"),
    ("/api/preview", "link"),
    ("/api/avatar/upload", "img_url"),
    ("/api/pdf/generate", "source_url"),
    ("/api/rss/sync", "feed_url"),
    ("/api/metadata/fetch", "uri"),
    ("/api/health/ping", "remote_host"),
]

for idx, (path, param) in enumerate(endpoints_ssrf, start=1):
    burp_ssrf_list.append({
        "issue_id": f"burp-ssrf-00{idx}",
        "name": f"Server-Side Request Forgery in {path}",
        "host": "https://app.example.test",
        "path": path,
        "parameter": param,
        "severity": "High" if idx <= 7 else "Medium",
        "confidence": "Certain",
        "issue_background": f"The parameter '{param}' at {path} allows arbitrary outbound HTTP requests.",
        "request": f"POST {path} HTTP/1.1\r\nHost: app.example.test\r\n\r\n{param}=http://169.254.169.254/latest/meta-data/",
        "response": "HTTP/1.1 200 OK\r\n\r\n{\"ami-id\": \"ami-0123456789abcdef0\", \"instance-id\": \"i-0123456789abcdef0\"}",
        "evidence": "AWS Cloud metadata endpoint returned HTTP 200 with instance credentials."
    })

with open(os.path.join(DATA_DIR, "burp_ssrf.json"), "w") as f:
    json.dump(burp_ssrf_list, f, indent=2)


# ── 6. Nessus SSRF SARIF (10 findings) ─────────────────────────────────────────
nessus_ssrf_results = []
for idx in range(1, 11):
    # First 3 match burp_ssrf endpoints for cross-scanner dedup test
    path, param = endpoints_ssrf[idx - 1] if idx <= 3 else (f"/api/nessus_ssrf_{idx}", f"target_url_{idx}")
    nessus_ssrf_results.append({
        "ruleId": "ssrf",
        "message": {"text": f"Server-Side Request Forgery detected at {path} via '{param}'."},
        "level": "error" if idx <= 6 else "warning",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f"https://app.example.test{path}"}
            }
        }],
        "properties": {
            "host": "https://app.example.test",
            "path": path,
            "parameter": param,
            "request": f"POST {path} {param}=http://127.0.0.1:8080/admin",
            "response": "HTTP/1.1 200 OK Admin Console",
            "evidence": "Localhost loopback service accessible via SSRF payload.",
            "cwe_ids": ["CWE-918"]
        }
    })

nessus_ssrf_sarif = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Nessus Professional", "version": "10.6"}},
        "results": nessus_ssrf_results
    }]
}

with open(os.path.join(DATA_DIR, "nessus_ssrf.sarif"), "w") as f:
    json.dump(nessus_ssrf_sarif, f, indent=2)


# ── 7. CISA KEV Mock Catalog ───────────────────────────────────────────────────
cisa_kev_mock = {
    "title": "CISA Known Exploited Vulnerabilities Catalog (Mock)",
    "catalogVersion": "2024.01.01",
    "dateReleased": "2024-01-01",
    "count": 5,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 JNDI feature does not protect against attacker controlled LDAP.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known"
        },
        {
            "cveID": "CVE-2024-1001",
            "vendorProject": "Example",
            "product": "Web App",
            "vulnerabilityName": "SQL Injection in Login API",
            "dateAdded": "2024-02-15",
            "shortDescription": "Active exploitation of SQL injection in authentication endpoint.",
            "requiredAction": "Apply fix immediately.",
            "dueDate": "2024-03-01",
            "knownRansomwareCampaignUse": "Known"
        },
        {
            "cveID": "CVE-2024-2001",
            "vendorProject": "Example",
            "product": "Search Engine",
            "vulnerabilityName": "Reflected XSS in Search API",
            "dateAdded": "2024-03-10",
            "shortDescription": "Exploitation of XSS in search parameter.",
            "requiredAction": "Encode user input.",
            "dueDate": "2024-03-24",
            "knownRansomwareCampaignUse": "Unknown"
        }
    ]
}

with open(os.path.join(DATA_DIR, "cisa_kev_mock.json"), "w") as f:
    json.dump(cisa_kev_mock, f, indent=2)


# ── 8. EPSS Mock Data ─────────────────────────────────────────────────────────
epss_mock = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 12,
    "offset": 0,
    "limit": 100,
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.9750", "percentile": "0.9995", "date": "2024-01-01"},
        {"cve": "CVE-2024-1001", "epss": "0.8920", "percentile": "0.9540", "date": "2024-01-01"},
        {"cve": "CVE-2024-1002", "epss": "0.7410", "percentile": "0.8810", "date": "2024-01-01"},
        {"cve": "CVE-2024-1003", "epss": "0.6200", "percentile": "0.7900", "date": "2024-01-01"},
        {"cve": "CVE-2024-2001", "epss": "0.4500", "percentile": "0.6500", "date": "2024-01-01"},
        {"cve": "CVE-2024-2002", "epss": "0.3100", "percentile": "0.5200", "date": "2024-01-01"},
        {"cve": "CVE-2024-2003", "epss": "0.1500", "percentile": "0.3500", "date": "2024-01-01"}
    ]
}

with open(os.path.join(DATA_DIR, "epss_mock.json"), "w") as f:
    json.dump(epss_mock, f, indent=2)

print("All 8 synthetic dataset files generated successfully in data/")
