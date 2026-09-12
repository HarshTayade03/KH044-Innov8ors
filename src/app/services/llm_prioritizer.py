"""
services/llm_prioritizer.py — LLM-assisted contextual synthesis engine.

Supports Groq (free fast inference for demos), Gemini, OpenAI, and Mock providers.
Applies strict pre-call secret redaction and graceful offline fallbacks.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Any
from src.app.config import settings
from src.app.schemas.risk import LLMContext
from src.app.services.extractor import redact_secrets

logger = logging.getLogger(__name__)


class LLMPrioritizerService:
    def _validate_synthesis(self, value: dict[str, Any], provider: str) -> dict[str, Any]:
        """Normalize provider output before it can influence analyst-facing context."""
        bounded = dict(value)
        bounded.setdefault("provider_used", provider)
        bounded.setdefault("model_used", settings.llm_model or "unknown")
        bounded.setdefault("evidence_basis", [])
        bounded.setdefault("uncertainty", [])
        try:
            return LLMContext.model_validate(bounded).model_dump()
        except (TypeError, ValueError):
            logger.warning("LLM provider '%s' returned an invalid synthesis schema.", provider)
            raise

    def synthesize_context(
        self,
        issue_title: str,
        cwe_primary: str,
        views_dict: dict[str, Any] | None,
        sandbox_verdict: str,
        sandbox_evidence: list[dict[str, Any]] | None,
        asset_criticality: str,
        internet_facing: bool,
        threat_cves: list[str],
    ) -> dict[str, Any]:
        """
        Synthesize finding context, empirical sandbox evidence, and business impact.
        Returns a structured dictionary with LLM analysis.
        """
        # If LLM disabled, default to mock synthesis cleanly
        if not settings.llm_enabled:
            return self._mock_synthesis(
                issue_title, cwe_primary, sandbox_verdict, asset_criticality, "offline_disabled"
            )

        provider = (settings.llm_provider or "groq").lower()
        api_key = settings.llm_api_key.strip()

        if provider != "mock" and not api_key:
            logger.warning(f"LLM provider '{provider}' requested but no API key configured. Falling back to mock.")
            return self._mock_synthesis(
                issue_title, cwe_primary, sandbox_verdict, asset_criticality, f"mock_missing_key_{provider}"
            )

        # Build prompt payload with secret redaction
        raw_prompt = (
            f"Vulnerability Title: {issue_title}\n"
            f"Primary CWE: {cwe_primary}\n"
            f"Asset Criticality: {asset_criticality} (Internet Facing: {internet_facing})\n"
            f"Known CVEs: {threat_cves}\n"
            f"Empirical Sandbox Verdict: {sandbox_verdict}\n"
            f"Contextual Views: {json.dumps(views_dict or {})}\n"
            f"Sandbox Evidence Excerpts: {json.dumps(sandbox_evidence or [])}\n"
        )
        redacted_prompt = redact_secrets(raw_prompt) or raw_prompt

        system_instruction = (
            "You are an expert cybersecurity triage analyst. Analyze the provided vulnerability findings and empirical sandbox test evidence.\n"
            "Return ONLY a valid JSON object matching this exact schema:\n"
            "{\n"
            '  "exploitability_assessment": "Short narrative assessment of real exploitability anchored in sandbox probe evidence.",\n'
            '  "business_impact_analysis": "Short narrative of business impact based on asset criticality and exposure.",\n'
            '  "remediation_guidance": "Specific, actionable technical remediation steps.",\n'
            '  "evidence_basis": ["Specific input or artifact supporting the assessment."],\n'
            '  "uncertainty": ["What remains unverified or simulation-limited."],\n'
            '  "confidence_score": 0.85\n'
            "}"
        )

        try:
            if provider == "groq":
                return self._validate_synthesis(
                    self._call_groq(redacted_prompt, system_instruction, api_key), provider
                )
            elif provider == "openai":
                return self._validate_synthesis(
                    self._call_openai(redacted_prompt, system_instruction, api_key), provider
                )
            elif provider == "gemini":
                return self._validate_synthesis(
                    self._call_gemini(redacted_prompt, system_instruction, api_key), provider
                )
            else:
                return self._mock_synthesis(
                    issue_title, cwe_primary, sandbox_verdict, asset_criticality, "mock_provider"
                )
        except Exception as exc:
            logger.warning(f"LLM API call to provider '{provider}' failed: {exc}. Falling back to mock synthesis.")
            return self._mock_synthesis(
                issue_title, cwe_primary, sandbox_verdict, asset_criticality, f"mock_fallback_error_{provider}"
            )

    def _call_groq(self, prompt: str, system: str, api_key: str) -> dict[str, Any]:
        """Call Groq API (OpenAI-compatible chat completions)."""
        model = settings.llm_model or "llama-3.3-70b-versatile"
        url = "https://api.groq.com/openai/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AI-Assisted Triage/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content_str = data["choices"][0]["message"]["content"]
            parsed = json.loads(content_str)
            parsed["provider_used"] = "groq"
            parsed["model_used"] = model
            return parsed

    def _call_openai(self, prompt: str, system: str, api_key: str) -> dict[str, Any]:
        """Call OpenAI API (chat completions)."""
        model = settings.llm_model or "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AI-Assisted Triage/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content_str = data["choices"][0]["message"]["content"]
            parsed = json.loads(content_str)
            parsed["provider_used"] = "openai"
            parsed["model_used"] = model
            return parsed

    def _call_gemini(self, prompt: str, system: str, api_key: str) -> dict[str, Any]:
        """Call Google Gemini REST API."""
        model = settings.llm_model or "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": f"{system}\n\n{prompt}"}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content_str = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(content_str)
            parsed["provider_used"] = "gemini"
            parsed["model_used"] = model
            return parsed

    def _mock_synthesis(
        self, issue_title: str, cwe: str, sandbox_status: str, asset_crit: str, provider_tag: str
    ) -> dict[str, Any]:
        """Deterministic offline fallback synthesis when LLM is offline or disabled."""
        if sandbox_status == "simulated_match":
            expl = f"Empirical lab validation ({sandbox_status}) confirmed probe reproducibility for {cwe} under test conditions."
            conf = 0.85
        elif sandbox_status == "simulated_no_match":
            expl = f"Empirical lab validation ({sandbox_status}) failed to reproduce {cwe} probe response; finding priority downgraded."
            conf = 0.65
        else:
            expl = f"Sandbox validation outcome ({sandbox_status}) is inconclusive; relying on multi-view scanner metrics for {cwe}."
            conf = 0.50

        return LLMContext(
            exploitability_assessment=expl,
            business_impact_analysis=f"Asset criticality '{asset_crit}' requires prioritized triage and remediation scoping.",
            remediation_guidance=f"Apply strict input validation, output encoding, or parameterized queries to mitigate {cwe}.",
            evidence_basis=[f"sandbox_verdict={sandbox_status}", f"cwe={cwe}"],
            uncertainty=["Offline simulation does not prove exploitability."],
            confidence_score=conf,
            provider_used=provider_tag,
            model_used="deterministic-rules-engine",
        ).model_dump()


llm_prioritizer_service = LLMPrioritizerService()
