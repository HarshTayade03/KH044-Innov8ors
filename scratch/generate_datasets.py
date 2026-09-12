"""
scratch/generate_datasets.py — Generator for synthetic vulnerability findings.

Generates findings across 8 dataset files:
- 50 SQLi (25 Burp SARIF, 25 Nessus JSON)
- 40 XSS (20 Burp SARIF, 20 OWASP ZAP JSON)
- 20 SSRF (10 Burp JSON, 10 Nessus SARIF)
- 15 Snyk SCA findings (dependency CVEs)
- 15 Trivy container scan findings (OS/library CVEs)
- CISA KEV Mock catalog (12 entries)
- EPSS Mock data (30 entries)
"""

import json
import os

# Use a repository-relative path so this runs correctly on any machine.
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DATA_DIR = os.path.abspath(DATA_DIR)
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
    ("/api/user", "name"),  # Endpoint same as #2, but param differs (id vs name) -> MUST STAY SEPARATE
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
print("Generated burp_sqli.sarif")


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
print("Generated nessus_sqli.json")


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
    rule_id = "xss" if idx <= 14 else "CWE-80"  # child CWE variant test
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
print("Generated burp_xss.sarif")


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
print("Generated zap_xss.json")


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
print("Generated burp_ssrf.json")


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
print("Generated nessus_ssrf.sarif")


# ── 7. Snyk SCA JSON (15 findings) ────────────────────────────────────────────
snyk_sca_list = [
    {
        "id": "SNYK-JAVA-LOG4J-2314720",
        "package_name": "log4j-core", "package_version": "2.14.1",
        "fixed_in": ["2.17.1"], "cve": "CVE-2021-44228", "cwe": ["CWE-502"],
        "severity": "Critical", "cvss_score": 10.0,
        "title": "Remote Code Execution (Log4Shell)",
        "file": "pom.xml",
        "description": "A flaw was found in the Apache Log4j 2 logging framework. The log4j2-core package allows remote code execution via JNDI lookup when attacker-controlled data is logged.",
        "package_manager": "maven", "from": ["log4j-core@2.14.1"]
    },
    {
        "id": "SNYK-JAVA-LOG4J-2314721",
        "package_name": "log4j-core", "package_version": "2.15.0",
        "fixed_in": ["2.17.1"], "cve": "CVE-2021-45046", "cwe": ["CWE-502"],
        "severity": "Critical", "cvss_score": 9.0,
        "title": "Remote Code Execution (Log4j2 incomplete fix)",
        "file": "build.gradle",
        "description": "The fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete. A remote attacker can execute arbitrary code via a JNDI lookup.",
        "package_manager": "gradle", "from": ["log4j-core@2.15.0"]
    },
    {
        "id": "SNYK-JAVA-SPRINGFRAMEWORK-2436751",
        "package_name": "spring-webmvc", "package_version": "5.3.17",
        "fixed_in": ["5.3.18"], "cve": "CVE-2022-22965", "cwe": ["CWE-94"],
        "severity": "Critical", "cvss_score": 9.8,
        "title": "Remote Code Execution (Spring4Shell)",
        "file": "pom.xml",
        "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.",
        "package_manager": "maven", "from": ["spring-webmvc@5.3.17"]
    },
    {
        "id": "SNYK-JAVA-COMMONSTEXT-3316oss",
        "package_name": "commons-text", "package_version": "1.9",
        "fixed_in": ["1.10.0"], "cve": "CVE-2022-42889", "cwe": ["CWE-94"],
        "severity": "Critical", "cvss_score": 9.8,
        "title": "Remote Code Execution via String Interpolation (Text4Shell)",
        "file": "pom.xml",
        "description": "Apache Commons Text performs variable interpolation that can result in arbitrary code execution via crafted interpolation expressions.",
        "package_manager": "maven", "from": ["commons-text@1.9"]
    },
    {
        "id": "SNYK-JAVA-NETTYCODECHTTP-2314722",
        "package_name": "netty-codec-http", "package_version": "4.1.77.Final",
        "fixed_in": ["4.1.79.Final"], "cve": "CVE-2022-24823", "cwe": ["CWE-668"],
        "severity": "Medium", "cvss_score": 5.5,
        "title": "Information Disclosure via Temporary Directory",
        "file": "pom.xml",
        "description": "If temporary files are created in a shared directory, an attacker can read them.",
        "package_manager": "maven", "from": ["netty-codec-http@4.1.77.Final"]
    },
    {
        "id": "SNYK-NPM-JSONWEBTOKEN-3180026",
        "package_name": "jsonwebtoken", "package_version": "8.5.1",
        "fixed_in": ["9.0.0"], "cve": "CVE-2022-23529", "cwe": ["CWE-1286"],
        "severity": "High", "cvss_score": 7.6,
        "title": "Remote Code Execution via Key Injection",
        "file": "package.json",
        "description": "jsonwebtoken <=8.5.1 contains a security flaw in the verify function that can allow unauthorized privilege escalation.",
        "package_manager": "npm", "from": ["jsonwebtoken@8.5.1"]
    },
    {
        "id": "SNYK-NPM-AXIOS-2349233",
        "package_name": "axios", "package_version": "0.21.1",
        "fixed_in": ["0.21.2"], "cve": "CVE-2021-3749", "cwe": ["CWE-400"],
        "severity": "High", "cvss_score": 7.5,
        "title": "Regular Expression Denial of Service (ReDoS)",
        "file": "package.json",
        "description": "Axios NPM package before 0.21.2 is vulnerable to Regular Expression Denial of Service via the trim function.",
        "package_manager": "npm", "from": ["axios@0.21.1"]
    },
    {
        "id": "SNYK-PYTHON-PILLOW-2330861",
        "package_name": "Pillow", "package_version": "8.3.1",
        "fixed_in": ["8.3.2"], "cve": "CVE-2021-34552", "cwe": ["CWE-119"],
        "severity": "Critical", "cvss_score": 9.8,
        "title": "Buffer Overflow",
        "file": "requirements.txt",
        "description": "Pillow through 8.3.1 allows arbitrary code execution via a crafted TIFF file.",
        "package_manager": "pip", "from": ["Pillow@8.3.1"]
    },
    {
        "id": "SNYK-PYTHON-DJANGO-3180027",
        "package_name": "Django", "package_version": "3.2.12",
        "fixed_in": ["3.2.13"], "cve": "CVE-2022-28347", "cwe": ["CWE-89"],
        "severity": "Critical", "cvss_score": 9.8,
        "title": "SQL Injection via QuerySet.annotate(), aggregate(), extra()",
        "file": "requirements.txt",
        "description": "Django QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases using a crafted dictionary.",
        "package_manager": "pip", "from": ["Django@3.2.12"]
    },
    {
        "id": "SNYK-RUBY-NOKOGIRI-1079720",
        "package_name": "nokogiri", "package_version": "1.12.5",
        "fixed_in": ["1.13.2"], "cve": "CVE-2022-24836", "cwe": ["CWE-400"],
        "severity": "High", "cvss_score": 7.5,
        "title": "Denial of Service via Inefficient Regular Expression",
        "file": "Gemfile.lock",
        "description": "Nokogiri is vulnerable to ReDoS via the HTML4 parser's handling of <br due to the regular expression detecting whether the tag is a valid HTML4 tag.",
        "package_manager": "rubygems", "from": ["nokogiri@1.12.5"]
    },
    {
        "id": "SNYK-JAVA-JACKSON-2314723",
        "package_name": "jackson-databind", "package_version": "2.13.0",
        "fixed_in": ["2.13.1"], "cve": "CVE-2020-36518", "cwe": ["CWE-787"],
        "severity": "High", "cvss_score": 7.5,
        "title": "Stack-based Buffer Overflow",
        "file": "pom.xml",
        "description": "jackson-databind before 2.13.1 has a Java StackOverflow exception and denial of service via a large depth of nested objects.",
        "package_manager": "maven", "from": ["jackson-databind@2.13.0"]
    },
    {
        "id": "SNYK-NPM-LODASH-567746",
        "package_name": "lodash", "package_version": "4.17.20",
        "fixed_in": ["4.17.21"], "cve": "CVE-2021-23337", "cwe": ["CWE-77"],
        "severity": "High", "cvss_score": 7.2,
        "title": "Command Injection via template()",
        "file": "package-lock.json",
        "description": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
        "package_manager": "npm", "from": ["lodash@4.17.20"]
    },
    {
        "id": "SNYK-NPM-PATHPARSE-1952824",
        "package_name": "path-parse", "package_version": "1.0.6",
        "fixed_in": ["1.0.7"], "cve": "CVE-2021-23343", "cwe": ["CWE-400"],
        "severity": "Medium", "cvss_score": 5.3,
        "title": "Regular Expression Denial of Service (ReDoS)",
        "file": "yarn.lock",
        "description": "path-parse is vulnerable to ReDoS via splitDeviceRe, splitTailRe, and splitPathRe regular expressions.",
        "package_manager": "npm", "from": ["path-parse@1.0.6"]
    },
    {
        "id": "SNYK-PYTHON-CRYPTOGRAPHY-3248428",
        "package_name": "cryptography", "package_version": "37.0.1",
        "fixed_in": ["39.0.1"], "cve": "CVE-2023-0286", "cwe": ["CWE-843"],
        "severity": "High", "cvss_score": 7.4,
        "title": "Type Confusion in X.509 GeneralName",
        "file": "requirements.txt",
        "description": "There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.",
        "package_manager": "pip", "from": ["cryptography@37.0.1"]
    },
    {
        "id": "SNYK-JAVA-SPRINGFRAMEWORKWEB-3170853",
        "package_name": "spring-web", "package_version": "5.3.18",
        "fixed_in": ["5.3.19"], "cve": "CVE-2022-22950", "cwe": ["CWE-400"],
        "severity": "Medium", "cvss_score": 6.5,
        "title": "Denial of Service via SPEL Expression",
        "file": "pom.xml",
        "description": "Spring Framework can be vulnerable to a DoS attack through a specially crafted SpEL expression.",
        "package_manager": "maven", "from": ["spring-web@5.3.18"]
    },
]

with open(os.path.join(DATA_DIR, "snyk_sca.json"), "w") as f:
    json.dump(snyk_sca_list, f, indent=2)
print("Generated snyk_sca.json")


# ── 8. Trivy Container JSON (15 findings) ─────────────────────────────────────
trivy_container_list = [
    {
        "target": "auth-service:2.1.0", "type": "library",
        "vulnerability_id": "CVE-2022-0778", "pkg_name": "openssl",
        "installed_version": "1.1.1k", "fixed_version": "1.1.1n",
        "severity": "High", "title": "Infinite Loop in BN_mod_sqrt()",
        "description": "The BN_mod_sqrt() function contains a bug that can cause it to loop forever for non-prime moduli when parsing certificates with invalid explicit curve parameters.",
        "primary_url": "https://www.cve.org/CVERecord?id=CVE-2022-0778",
        "cwe_ids": ["CWE-835"]
    },
    {
        "target": "auth-service:2.1.0", "type": "library",
        "vulnerability_id": "CVE-2023-0286", "pkg_name": "openssl",
        "installed_version": "1.1.1k", "fixed_version": "1.1.1t",
        "severity": "High", "title": "X.400 Address Type Confusion in X.509 GeneralName",
        "description": "Type confusion vulnerability in X.400 address processing in X.509 GeneralName can lead to reads from invalid memory.",
        "primary_url": "https://www.cve.org/CVERecord?id=CVE-2023-0286",
        "cwe_ids": ["CWE-843"]
    },
    {
        "target": "api-gateway:1.5.3", "type": "library",
        "vulnerability_id": "CVE-2021-44228", "pkg_name": "log4j",
        "installed_version": "2.14.1", "fixed_version": "2.17.1",
        "severity": "Critical", "title": "Log4Shell Remote Code Execution via JNDI Lookup",
        "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints, allowing RCE.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "cwe_ids": ["CWE-502", "CWE-917"]
    },
    {
        "target": "api-gateway:1.5.3", "type": "library",
        "vulnerability_id": "CVE-2022-22965", "pkg_name": "spring-beans",
        "installed_version": "5.3.15", "fixed_version": "5.3.18",
        "severity": "Critical", "title": "Spring4Shell - Remote Code Execution in Spring Framework",
        "description": "A Spring MVC application running on JDK 9+ may be vulnerable to RCE via data binding.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
        "cwe_ids": ["CWE-94"]
    },
    {
        "target": "web-frontend:3.0.1", "type": "library",
        "vulnerability_id": "CVE-2022-1471", "pkg_name": "snakeyaml",
        "installed_version": "1.30", "fixed_version": "2.0",
        "severity": "Critical", "title": "SnakeYaml Constructor Deserialization Remote Code Execution",
        "description": "SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization, allowing RCE.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-1471",
        "cwe_ids": ["CWE-502"]
    },
    {
        "target": "web-frontend:3.0.1", "type": "library",
        "vulnerability_id": "CVE-2021-23017", "pkg_name": "nginx",
        "installed_version": "1.21.0", "fixed_version": "1.21.1",
        "severity": "High", "title": "1-byte Memory Overwrite in Resolver",
        "description": "A security issue in nginx resolver allows an attacker to forge UDP packets causing a 1-byte memory overwrite.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        "cwe_ids": ["CWE-193"]
    },
    {
        "target": "payment-service:1.2.0", "type": "os",
        "vulnerability_id": "CVE-2021-3711", "pkg_name": "openssl",
        "installed_version": "1.1.1j", "fixed_version": "1.1.1l",
        "severity": "Critical", "title": "SM2 Decryption Buffer Overflow",
        "description": "OpenSSL contains a buffer overflow vulnerability in EVP_PKEY_decrypt due to miscalculated SM2 decryption buffer size.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-3711",
        "cwe_ids": ["CWE-120"]
    },
    {
        "target": "payment-service:1.2.0", "type": "library",
        "vulnerability_id": "CVE-2022-42898", "pkg_name": "krb5",
        "installed_version": "1.19.2", "fixed_version": "1.19.4",
        "severity": "High", "title": "Integer Overflow in PAC Parsing",
        "description": "MIT Kerberos 5 before 1.19.4 has integer overflows in PAC parsing that may lead to RCE on 32-bit platforms or DoS on others.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-42898",
        "cwe_ids": ["CWE-190"]
    },
    {
        "target": "data-processor:0.9.5", "type": "library",
        "vulnerability_id": "CVE-2023-25690", "pkg_name": "httpd",
        "installed_version": "2.4.54", "fixed_version": "2.4.56",
        "severity": "Critical", "title": "HTTP Request Smuggling via mod_proxy",
        "description": "Apache HTTP Server mod_proxy configurations allow HTTP Request Smuggling via RewriteRule or ProxyPassMatch.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-25690",
        "cwe_ids": ["CWE-444"]
    },
    {
        "target": "data-processor:0.9.5", "type": "library",
        "vulnerability_id": "CVE-2022-31692", "pkg_name": "spring-security-web",
        "installed_version": "5.6.5", "fixed_version": "5.6.9",
        "severity": "High", "title": "Authorization Bypass via Forward or Include Dispatcher Types",
        "description": "Spring Security before 5.6.9 is susceptible to authorization rule bypass under certain conditions affecting method security.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-31692",
        "cwe_ids": ["CWE-284"]
    },
    {
        "target": "ml-pipeline:4.2.1", "type": "library",
        "vulnerability_id": "CVE-2022-40897", "pkg_name": "setuptools",
        "installed_version": "60.10.0", "fixed_version": "65.5.1",
        "severity": "High", "title": "Regular Expression Denial of Service (ReDoS) in package_index.py",
        "description": "Python setuptools before 65.5.1 allows ReDoS via the PackageIndex.url_ok() function.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-40897",
        "cwe_ids": ["CWE-400"]
    },
    {
        "target": "ml-pipeline:4.2.1", "type": "library",
        "vulnerability_id": "CVE-2023-32681", "pkg_name": "requests",
        "installed_version": "2.28.2", "fixed_version": "2.31.0",
        "severity": "Medium", "title": "Unintended Leak of Proxy-Authorization Header",
        "description": "Requests library before 2.31.0 leaks the Proxy-Authorization header to destination servers when redirected to HTTPS.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
        "cwe_ids": ["CWE-200"]
    },
    {
        "target": "notification-service:1.0.3", "type": "library",
        "vulnerability_id": "CVE-2022-25857", "pkg_name": "snakeyaml",
        "installed_version": "1.29", "fixed_version": "1.31",
        "severity": "High", "title": "Denial of Service via Stack Overflow",
        "description": "SnakeYaml before 1.31 is vulnerable to DoS due to missing nested depth limitation for collections.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-25857",
        "cwe_ids": ["CWE-400"]
    },
    {
        "target": "notification-service:1.0.3", "type": "os",
        "vulnerability_id": "CVE-2023-44487", "pkg_name": "golang.org/x/net",
        "installed_version": "0.10.0", "fixed_version": "0.17.0",
        "severity": "High", "title": "HTTP/2 Rapid Reset Attack (Denial of Service)",
        "description": "The HTTP/2 protocol allows DoS because request cancellation can reset many streams quickly, exploited in the wild as Rapid Reset.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
        "cwe_ids": ["CWE-400"]
    },
    {
        "target": "admin-panel:2.0.0", "type": "os",
        "vulnerability_id": "CVE-2023-28484", "pkg_name": "libxml2",
        "installed_version": "2.9.13", "fixed_version": "2.10.4",
        "severity": "Medium", "title": "NULL Pointer Dereference in xmlSchemaFixupComplexType()",
        "description": "Parsing of certain invalid XSD schemas in libxml2 before 2.10.4 can lead to a NULL pointer dereference and segfault.",
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28484",
        "cwe_ids": ["CWE-476"]
    },
]

with open(os.path.join(DATA_DIR, "trivy_container.json"), "w") as f:
    json.dump(trivy_container_list, f, indent=2)
print("Generated trivy_container.json")


# ── 9. CISA KEV Mock Catalog ───────────────────────────────────────────────────
cisa_kev_mock = {
    "title": "CISA Known Exploited Vulnerabilities Catalog (Mock)",
    "catalogVersion": "2024.09.01",
    "dateReleased": "2024-09-01",
    "count": 12,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known"
        },
        {
            "cveID": "CVE-2021-45046", "vendorProject": "Apache", "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Deserialization of Untrusted Data Vulnerability",
            "dateAdded": "2021-12-14",
            "shortDescription": "Apache Log4j2 contains a deserialization vulnerability due to the incomplete fix of CVE-2021-44228.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2021-12-28",
            "knownRansomwareCampaignUse": "Known"
        },
        {
            "cveID": "CVE-2022-22965", "vendorProject": "VMware", "product": "Spring Framework",
            "vulnerabilityName": "Spring Framework JDK 9+ Remote Code Execution Vulnerability",
            "dateAdded": "2022-04-04",
            "shortDescription": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to RCE via data binding.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2022-04-25",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2022-42889", "vendorProject": "Apache", "product": "Commons Text",
            "vulnerabilityName": "Apache Commons Text Improper Input Validation Vulnerability",
            "dateAdded": "2022-12-02",
            "shortDescription": "Apache Commons Text variable interpolation allows remote code execution via crafted expressions.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2022-12-23",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2021-3711", "vendorProject": "OpenSSL", "product": "OpenSSL",
            "vulnerabilityName": "OpenSSL SM2 Decryption Buffer Overflow Vulnerability",
            "dateAdded": "2022-01-10",
            "shortDescription": "OpenSSL contains a buffer overflow in EVP_PKEY_decrypt due to miscalculated SM2 decryption buffer size.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2022-02-01",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2023-44487", "vendorProject": "Multiple", "product": "HTTP/2",
            "vulnerabilityName": "HTTP/2 Rapid Reset Attack Vulnerability",
            "dateAdded": "2023-10-10",
            "shortDescription": "HTTP/2 protocol allows DoS because request cancellation can reset many streams quickly, exploited in the wild.",
            "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2023-10-31",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2023-25690", "vendorProject": "Apache", "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server HTTP Request Smuggling Vulnerability",
            "dateAdded": "2023-04-10",
            "shortDescription": "mod_proxy configurations on Apache HTTP Server 2.4.0-2.4.55 allow HTTP Request Smuggling.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2023-05-01",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2024-1001", "vendorProject": "Example", "product": "Web App",
            "vulnerabilityName": "SQL Injection in Login API",
            "dateAdded": "2024-02-15",
            "shortDescription": "Active exploitation of SQL injection in authentication endpoint observed in the wild.",
            "requiredAction": "Apply fix immediately.", "dueDate": "2024-03-01",
            "knownRansomwareCampaignUse": "Known"
        },
        {
            "cveID": "CVE-2024-2001", "vendorProject": "Example", "product": "Search Engine",
            "vulnerabilityName": "Reflected XSS in Search API",
            "dateAdded": "2024-03-10",
            "shortDescription": "Exploitation of XSS in search parameter resulting in session hijacking.",
            "requiredAction": "Encode and validate user input.", "dueDate": "2024-03-24",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2022-22950", "vendorProject": "VMware", "product": "Spring Framework",
            "vulnerabilityName": "Spring Framework Denial of Service via SpEL Expression",
            "dateAdded": "2022-06-01",
            "shortDescription": "Spring Framework can be vulnerable to DoS via a crafted SpEL expression.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2022-06-22",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2022-1471", "vendorProject": "SnakeYaml", "product": "SnakeYaml",
            "vulnerabilityName": "SnakeYaml Constructor Deserialization Remote Code Execution",
            "dateAdded": "2022-12-05",
            "shortDescription": "SnakeYaml's Constructor() class does not restrict types instantiated during deserialization, allowing RCE.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2022-12-26",
            "knownRansomwareCampaignUse": "Unknown"
        },
        {
            "cveID": "CVE-2022-28347", "vendorProject": "Django", "product": "Django",
            "vulnerabilityName": "Django SQL Injection via QuerySet Methods",
            "dateAdded": "2022-05-01",
            "shortDescription": "Django QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection via crafted kwargs.",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2022-05-22",
            "knownRansomwareCampaignUse": "Unknown"
        },
    ]
}

with open(os.path.join(DATA_DIR, "cisa_kev_mock.json"), "w") as f:
    json.dump(cisa_kev_mock, f, indent=2)
print("Generated cisa_kev_mock.json")


# ── 10. EPSS Mock Data ─────────────────────────────────────────────────────────
epss_mock = {
    "status": "OK", "status-code": 200, "version": "1.0",
    "access": "public", "total": 30, "offset": 0, "limit": 100,
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.9750", "percentile": "0.9995", "date": "2024-09-01"},
        {"cve": "CVE-2021-45046", "epss": "0.9600", "percentile": "0.9989", "date": "2024-09-01"},
        {"cve": "CVE-2022-22965", "epss": "0.9420", "percentile": "0.9975", "date": "2024-09-01"},
        {"cve": "CVE-2022-42889", "epss": "0.9100", "percentile": "0.9952", "date": "2024-09-01"},
        {"cve": "CVE-2021-3711",  "epss": "0.8850", "percentile": "0.9921", "date": "2024-09-01"},
        {"cve": "CVE-2023-44487", "epss": "0.8600", "percentile": "0.9898", "date": "2024-09-01"},
        {"cve": "CVE-2023-25690", "epss": "0.8200", "percentile": "0.9870", "date": "2024-09-01"},
        {"cve": "CVE-2022-1471",  "epss": "0.8050", "percentile": "0.9830", "date": "2024-09-01"},
        {"cve": "CVE-2022-28347", "epss": "0.7800", "percentile": "0.9792", "date": "2024-09-01"},
        {"cve": "CVE-2024-1001",  "epss": "0.8920", "percentile": "0.9540", "date": "2024-09-01"},
        {"cve": "CVE-2024-1002",  "epss": "0.7410", "percentile": "0.8810", "date": "2024-09-01"},
        {"cve": "CVE-2024-1003",  "epss": "0.6200", "percentile": "0.7900", "date": "2024-09-01"},
        {"cve": "CVE-2024-1004",  "epss": "0.5900", "percentile": "0.7650", "date": "2024-09-01"},
        {"cve": "CVE-2024-1005",  "epss": "0.5500", "percentile": "0.7400", "date": "2024-09-01"},
        {"cve": "CVE-2024-2001",  "epss": "0.4500", "percentile": "0.6500", "date": "2024-09-01"},
        {"cve": "CVE-2024-2002",  "epss": "0.3100", "percentile": "0.5200", "date": "2024-09-01"},
        {"cve": "CVE-2024-2003",  "epss": "0.1500", "percentile": "0.3500", "date": "2024-09-01"},
        {"cve": "CVE-2024-2004",  "epss": "0.1200", "percentile": "0.3100", "date": "2024-09-01"},
        {"cve": "CVE-2024-2005",  "epss": "0.0980", "percentile": "0.2850", "date": "2024-09-01"},
        {"cve": "CVE-2022-0778",  "epss": "0.7620", "percentile": "0.9410", "date": "2024-09-01"},
        {"cve": "CVE-2023-0286",  "epss": "0.5800", "percentile": "0.8100", "date": "2024-09-01"},
        {"cve": "CVE-2022-24823", "epss": "0.2300", "percentile": "0.4800", "date": "2024-09-01"},
        {"cve": "CVE-2022-23529", "epss": "0.4100", "percentile": "0.6200", "date": "2024-09-01"},
        {"cve": "CVE-2021-3749",  "epss": "0.3400", "percentile": "0.5700", "date": "2024-09-01"},
        {"cve": "CVE-2021-34552", "epss": "0.6900", "percentile": "0.8600", "date": "2024-09-01"},
        {"cve": "CVE-2020-36518", "epss": "0.5200", "percentile": "0.7200", "date": "2024-09-01"},
        {"cve": "CVE-2021-23337", "epss": "0.3700", "percentile": "0.6000", "date": "2024-09-01"},
        {"cve": "CVE-2022-42898", "epss": "0.4600", "percentile": "0.6700", "date": "2024-09-01"},
        {"cve": "CVE-2022-31692", "epss": "0.2800", "percentile": "0.5100", "date": "2024-09-01"},
        {"cve": "CVE-2023-28484", "epss": "0.1100", "percentile": "0.2600", "date": "2024-09-01"},
    ]
}

with open(os.path.join(DATA_DIR, "epss_mock.json"), "w") as f:
    json.dump(epss_mock, f, indent=2)
print("Generated epss_mock.json")

print("\nAll 10 synthetic dataset files generated successfully in data/")
print("Total scanner findings: 140 (50 SQLi + 40 XSS + 20 SSRF + 15 Snyk SCA + 15 Trivy container)")
print("Threat intel feeds:     2  (CISA KEV: 12 entries, EPSS: 30 entries)")
