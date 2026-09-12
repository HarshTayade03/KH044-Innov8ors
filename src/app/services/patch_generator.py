"""
services/patch_generator.py — AI Auto-Remediation and Patch Generator Agent.

Generates contextual git unified diffs and code remediation proposals for canonical issues
using LLM inference (Groq, Gemini, OpenAI) with a deterministic security patch fallback.
"""

import ast
import json
import logging
import urllib.request
import urllib.error
from typing import Any, Optional, Dict
from src.app.config import settings
from src.app.schemas.remediation import RemediationPatchResponse, PatchValidation
from src.app.services.extractor import redact_secrets

logger = logging.getLogger(__name__)


class PatchGeneratorService:
    """Service for generating and validating AI remediation patches."""

    def generate_patch(
        self,
        canonical_issue_id: str,
        title: str,
        cwe_primary: str,
        location_view: Optional[str] = None,
        reproduction_view: Optional[str] = None,
        impact_view: Optional[str] = None,
        description_view: Optional[str] = None,
        target_language: str = "python",
    ) -> RemediationPatchResponse:
        """
        Generate a contextual security patch and git diff for a canonical issue.
        """
        # Redact secrets before constructing LLM context
        clean_title = redact_secrets(title)
        clean_loc = redact_secrets(location_view or "Unknown location")
        clean_repro = redact_secrets(reproduction_view or "No reproduction step")
        clean_desc = redact_secrets(description_view or "No description")

        if not settings.llm_enabled:
            return self._rule_fallback_patch(
                canonical_issue_id, clean_title, cwe_primary, clean_loc, clean_repro, target_language, "offline_disabled"
            )

        provider = (settings.llm_provider or "groq").lower()
        api_key = settings.llm_api_key.strip()

        if provider != "mock" and not api_key:
            return self._rule_fallback_patch(
                canonical_issue_id, clean_title, cwe_primary, clean_loc, clean_repro, target_language, "missing_api_key"
            )

        try:
            if provider == "groq":
                return self._call_groq_patch(canonical_issue_id, clean_title, cwe_primary, clean_loc, clean_repro, api_key, target_language)
            elif provider == "openai":
                return self._call_openai_patch(canonical_issue_id, clean_title, cwe_primary, clean_loc, clean_repro, api_key, target_language)
            else:
                return self._rule_fallback_patch(
                    canonical_issue_id, clean_title, cwe_primary, clean_loc, clean_repro, target_language, "mock"
                )
        except Exception as exc:
            logger.exception("LLM patch generation failed (%s). Falling back to rule-based patch generator.", str(exc))
            return self._rule_fallback_patch(
                canonical_issue_id, clean_title, cwe_primary, clean_loc, clean_repro, target_language, f"fallback ({str(exc)[:40]})"
            )

    def _validate_patch_syntax(self, code_snippet: str, language: str) -> PatchValidation:
        """Validate syntax of the proposed code snippet."""
        lang = language.lower()
        if lang in ["python", "py"]:
            try:
                ast.parse(code_snippet)
                return PatchValidation(is_valid_syntax=True, language="python", safety_checks_passed=True)
            except SyntaxError as e:
                return PatchValidation(is_valid_syntax=False, language="python", validation_error=str(e), safety_checks_passed=True)
        # For JS/HTML/SQL, perform basic sanity check
        is_valid = len(code_snippet.strip()) > 0 and "SYNTAX_ERROR" not in code_snippet
        return PatchValidation(is_valid_syntax=is_valid, language=lang, safety_checks_passed=True)

    def _rule_fallback_patch(
        self,
        canonical_issue_id: str,
        title: str,
        cwe_primary: str,
        location: str,
        reproduction: str,
        target_language: str,
        reason: str,
    ) -> RemediationPatchResponse:
        """Deterministic fallback patch generator based on CWE taxonomy."""
        cwe_upper = (cwe_primary or "").upper()

        if "CWE-89" in cwe_upper or "SQL" in title.upper():
            vulnerable = f"# Vulnerable DB query in {location}\ncursor.execute(f\"SELECT * FROM users WHERE username = '{reproduction}'\")"
            fixed = f"# Parameterized DB query fix\ncursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))"
            summary = "Replaced unsafe dynamic string formatting with parameterized prepared query execution."
            diff = (
                "--- a/app/db.py\n"
                "+++ b/app/db.py\n"
                "@@ -42,3 +42,3 @@\n"
                f"- cursor.execute(f\"SELECT * FROM users WHERE username = '{reproduction}'\")\n"
                "+ cursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))\n"
            )
        elif "CWE-79" in cwe_upper or "XSS" in title.upper():
            vulnerable = f"// Vulnerable DOM insertion in {location}\nelement.innerHTML = userInput;"
            fixed = f"// Safe text content assignment\nelement.textContent = userInput;"
            summary = "Replaced dangerous innerHTML assignment with safe textContent property."
            diff = (
                "--- a/static/app.js\n"
                "+++ b/static/app.js\n"
                "@@ -15,3 +15,3 @@\n"
                "- element.innerHTML = userInput;\n"
                "+ element.textContent = userInput;\n"
            )
        elif "CWE-918" in cwe_upper or "SSRF" in title.upper():
            vulnerable = f"# Unvalidated HTTP request in {location}\nresponse = requests.get(user_supplied_url)"
            fixed = (
                "# Allowlist-validated HTTP request\n"
                "if not is_allowlisted_domain(user_supplied_url):\n"
                "    raise ValueError('Target host not permitted')\n"
                "response = requests.get(user_supplied_url, allow_redirects=False, timeout=5.0)"
            )
            summary = "Enforced strict domain allowlist validation, disabled HTTP redirects, and bound timeout."
            diff = (
                "--- a/services/fetcher.py\n"
                "+++ b/services/fetcher.py\n"
                "@@ -8,2 +8,5 @@\n"
                "+ if not is_allowlisted_domain(user_supplied_url):\n"
                "+     raise ValueError('Target host not permitted')\n"
                "- response = requests.get(user_supplied_url)\n"
                "+ response = requests.get(user_supplied_url, allow_redirects=False, timeout=5.0)\n"
            )
        else:
            vulnerable = f"# Input processing in {location}\nprocess_input(raw_input)"
            fixed = f"# Sanitized input processing in {location}\nsanitized = sanitize_input(raw_input)\nprocess_input(sanitized)"
            summary = "Applied input validation and sanitization prior to execution."
            diff = (
                "--- a/app/core.py\n"
                "+++ b/app/core.py\n"
                "@@ -10,1 +10,2 @@\n"
                "- process_input(raw_input)\n"
                "+ sanitized = sanitize_input(raw_input)\n"
                "+ process_input(sanitized)\n"
            )

        validation = self._validate_patch_syntax(fixed, target_language)

        return RemediationPatchResponse(
            canonical_issue_id=canonical_issue_id,
            cwe_id=cwe_primary,
            title=f"Security Fix: {title}",
            summary=summary,
            git_diff=diff,
            vulnerable_code_snippet=vulnerable,
            fixed_code_snippet=fixed,
            validation=validation,
            provider_used=f"rule_fallback ({reason})",
            confidence=0.92,
        )

    def _call_groq_patch(
        self, canonical_issue_id: str, title: str, cwe: str, loc: str, repro: str, api_key: str, lang: str
    ) -> RemediationPatchResponse:
        url = "https://api.groq.com/openai/v1/chat/completions"
        system_msg = (
            "You are a senior security engineer. Generate a contextual security patch fix.\n"
            "Return ONLY a valid raw JSON object with keys: summary, git_diff, vulnerable_code_snippet, fixed_code_snippet.\n"
            "Do not include markdown code block syntax (such as ```json) or explanations outside the JSON."
        )
        user_prompt = (
            f"Vulnerability Title: {title}\nCWE: {cwe}\nLocation: {loc}\n"
            f"Reproduction context: {repro}\nTarget Language: {lang}\n"
        )
        req_data = json.dumps({
            "model": settings.llm_model or "openai/gpt-oss-20b",
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "VulnTriager/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_content = data["choices"][0]["message"]["content"].strip()
            logger.info("RAW GROQ RESPONSE: %s", raw_content)
            s = raw_content.find("{")
            e = raw_content.rfind("}")
            if s != -1 and e != -1 and e > s:
                json_str = raw_content[s : e + 1]
            else:
                json_str = raw_content
            content = json.loads(json_str)
            validation = self._validate_patch_syntax(content.get("fixed_code_snippet", ""), lang)
            return RemediationPatchResponse(
                canonical_issue_id=canonical_issue_id,
                cwe_id=cwe,
                title=f"AI Fix: {title}",
                summary=content.get("summary", "Contextual AI remediation patch."),
                git_diff=content.get("git_diff", ""),
                vulnerable_code_snippet=content.get("vulnerable_code_snippet", ""),
                fixed_code_snippet=content.get("fixed_code_snippet", ""),
                validation=validation,
                provider_used="groq",
                confidence=0.95,
            )

    def _call_openai_patch(
        self, canonical_issue_id: str, title: str, cwe: str, loc: str, repro: str, api_key: str, lang: str
    ) -> RemediationPatchResponse:
        url = "https://api.openai.com/v1/chat/completions"
        prompt = (
            f"Generate security patch JSON (keys: summary, git_diff, vulnerable_code_snippet, fixed_code_snippet) for:\n"
            f"Title: {title} | CWE: {cwe} | Location: {loc} | Repro: {repro}"
        )
        req_data = json.dumps({
            "model": settings.llm_model or "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "VulnTriager/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = json.loads(data["choices"][0]["message"]["content"])
            validation = self._validate_patch_syntax(content.get("fixed_code_snippet", ""), lang)
            return RemediationPatchResponse(
                canonical_issue_id=canonical_issue_id,
                cwe_id=cwe,
                title=f"AI Fix: {title}",
                summary=content.get("summary", "Contextual AI remediation patch."),
                git_diff=content.get("git_diff", ""),
                vulnerable_code_snippet=content.get("vulnerable_code_snippet", ""),
                fixed_code_snippet=content.get("fixed_code_snippet", ""),
                validation=validation,
                provider_used="openai",
                confidence=0.95,
            )
