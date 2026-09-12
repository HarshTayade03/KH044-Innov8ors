"""
config.py — Application configuration.

Reads all settings from environment variables (populated from .env file).
Exposes a single `settings` singleton imported by all other modules.

Decision log:
- pydantic-settings used instead of raw os.getenv() for type coercion and validation.
- Risk weights are validated to sum to 1.0 at import time so startup fails fast.
"""

import os
from pydantic_settings import BaseSettings
from pydantic import model_validator


class Settings(BaseSettings):
    # ── Database ──────────────────────────────────────────────────────────────
    database_path: str = "./ai-assisted-triage.db"

    # ── Sandbox ───────────────────────────────────────────────────────────────
    sandbox_enabled: bool = False
    sandbox_allowlist: str = "app.example.test,target.lab"
    sandbox_timeout_seconds: int = 30

    # ── Embedding Model ───────────────────────────────────────────────────────
    model_name: str = "all-MiniLM-L6-v2"
    model_allow_download: bool = False

    # ── Threat Intelligence ───────────────────────────────────────────────────
    kev_live: bool = False
    kev_data_path: str = "./data/cisa_kev_mock.json"
    epss_live: bool = False
    epss_data_path: str = "./data/epss_mock.json"
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    threat_feed_refresh_enabled: bool = False

    # ── Risk Score Weights ────────────────────────────────────────────────────
    risk_weight_cvss: float = 0.25
    risk_weight_epss: float = 0.20
    risk_weight_kev: float = 0.15
    risk_weight_asset: float = 0.15
    risk_weight_exposure: float = 0.15
    risk_weight_validation: float = 0.10

    # ── Future Scope Stubs ────────────────────────────────────────────────────
    slack_webhook_url: str = ""
    jira_url: str = ""
    jira_api_token: str = ""

    # ── LLM Prioritization ────────────────────────────────────────────────────
    llm_enabled: bool = False
    llm_provider: str = "groq"
    llm_model: str = "llama-3.3-70b-versatile"
    llm_api_key: str = ""

    # ── Application Metadata ──────────────────────────────────────────────────
    app_version: str = "0.1.0"
    app_name: str = "AI-Assisted Vulnerability Triage Platform"

    @model_validator(mode="after")
    def validate_risk_weights(self) -> "Settings":
        """Risk weights must sum to exactly 1.0. Fail fast at startup if misconfigured."""
        total = round(
            self.risk_weight_cvss
            + self.risk_weight_epss
            + self.risk_weight_kev
            + self.risk_weight_asset
            + self.risk_weight_exposure
            + self.risk_weight_validation,
            10,
        )
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                f"Risk weights must sum to 1.0, but they sum to {total}. "
                "Check RISK_WEIGHT_* values in your .env file."
            )
        return self

    @property
    def sandbox_allowlist_set(self) -> set[str]:
        """Return the sandbox allowlist as a set of hostnames for O(1) lookup."""
        return {h.strip() for h in self.sandbox_allowlist.split(",") if h.strip()}

    model_config = {
        "protected_namespaces": ("model_validate", "model_dump"),
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Module-level singleton — import this in all other modules:
#   from src.app.config import settings
settings = Settings()
