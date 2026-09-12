"""
services/risk_engine.py — Composite risk scoring and remediation tier assignment engine.

Defined according to docs/MODULE_SPECS/R0_baseline.md.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from src.app.config import settings
from src.app.schemas.dedup import CanonicalIssue
from src.app.schemas.risk import PriorityResult, RemediationTier, ThreatEnrichment
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.risk_repo import risk_repo
from src.app.repositories.validation_repo import EvidenceIntegrityError, validation_repo
from src.app.services.threat_intel import threat_intel_service
from src.app.services.llm_prioritizer import llm_prioritizer_service, llm_prioritizer


class RiskEngine:
    """Calculates composite risk score (0-100) and remediation tier for canonical issues."""

    def _get_asset_criticality_factor(self, criticality: Optional[str]) -> float:
        c = (criticality or "medium").lower()
        if c == "critical":
            return 1.0
        elif c == "high":
            return 0.75
        elif c == "medium":
            return 0.50
        elif c == "low":
            return 0.25
        return 0.50

    def calculate_priority(self, canonical_issue_id: str) -> PriorityResult:
        with dedup_repo.transaction():
            return self._calculate_priority(canonical_issue_id)

    def _calculate_priority(self, canonical_issue_id: str) -> PriorityResult:
        """
        Calculate composite risk score for a CanonicalIssue.
        """
        issue = dedup_repo.get_canonical_issue(canonical_issue_id)
        if not issue or not issue.active:
            raise ValueError(f"Canonical issue '{canonical_issue_id}' not found.")

        threat_intel_service.check_mode()

        # Aggregate finding details
        findings = []
        for fid in issue.source_finding_ids:
            f = findings_repo.get_normalized_finding(fid)
            if f:
                findings.append(f)

        if not findings:
            raise ValueError(f"No source findings found for issue '{canonical_issue_id}'.")

        # Use maximum severity/CVSS finding as primary anchor
        primary = max(findings, key=lambda x: x.vulnerability.cvss_score or 0.0)

        # Threat Intel enrichment for all CVEs
        all_cves = set()
        for f in findings:
            all_cves.update(f.vulnerability.cve_ids)

        threat_enrichments: list[ThreatEnrichment] = []
        for cve in sorted(all_cves):
            threat_enrichments.append(threat_intel_service.enrich_cve(cve))

        kev_flag = any(t.kev_flag for t in threat_enrichments)
        max_epss = max((t.epss_score for t in threat_enrichments), default=0.0)

        cvss_score = primary.vulnerability.cvss_score or 0.0
        asset_crit = primary.asset.criticality or "medium"
        internet_facing = primary.asset.internet_facing

        # Normalize factors (0.0 to 1.0)
        cvss_norm = cvss_score / 10.0
        epss_norm = max_epss
        kev_norm = 1.0 if kev_flag else 0.0
        asset_norm = self._get_asset_criticality_factor(asset_crit)
        exposure_norm = 1.0 if internet_facing else 0.5
        validation = validation_repo.latest_for_issue(canonical_issue_id)

        # Direct consumption of sandbox validation results
        if validation:
            v_status = validation.status.value
            if v_status == "simulated_match":
                conf = validation.confidence or 0.75
                val_norm = min(0.90, max(0.75, conf))
            elif v_status == "simulated_no_match":
                val_norm = 0.20
            else:
                val_norm = 0.50
        else:
            val_norm = 0.50

        # Weights from config
        w_cvss = settings.risk_weight_cvss
        w_epss = settings.risk_weight_epss
        w_kev = settings.risk_weight_kev
        w_asset = settings.risk_weight_asset
        w_exposure = settings.risk_weight_exposure
        w_validation = settings.risk_weight_validation

        weights_used = {
            "cvss": w_cvss,
            "epss": w_epss,
            "kev": w_kev,
            "asset": w_asset,
            "exposure": w_exposure,
            "validation": w_validation,
        }

        # Composite score
        raw_score = 100.0 * (
            w_cvss * cvss_norm
            + w_epss * epss_norm
            + w_kev * kev_norm
            + w_asset * asset_norm
            + w_exposure * exposure_norm
            + w_validation * val_norm
        )
        risk_score = round(min(100.0, max(0.0, raw_score)), 2)

        # Remediation Tier assignment rules
        if kev_flag or risk_score >= 80.0:
            tier = RemediationTier.IMMEDIATE
        elif risk_score >= 50.0:
            tier = RemediationTier.ACCELERATED
        else:
            tier = RemediationTier.STANDARD

        normalized = dict(cvss=cvss_norm, epss=epss_norm, kev=kev_norm, asset=asset_norm,
                          exposure=exposure_norm, validation=val_norm)
        contributions = {key: 100.0 * weights_used[key] * value for key, value in normalized.items()}
        explanation = [f"{key.upper()}: factor {normalized[key]:.4f} x weight {weights_used[key]:.4f} contributes {value:.2f} pts."
                       for key, value in contributions.items()]
        if validation:
            explanation.append(f"Validation factor ({val_norm:.2f}) uses latest {validation.status.value} offline simulation; simulation does not prove exploitability.")
        else:
            explanation.append("Validation uses a neutral 0.5 prior: no sandbox validation has run.")
        explanation.append("Threat intelligence uses synthetic mock files, not current live feeds.")
        if kev_flag:
            explanation.append("Immediate tier: CVE is present in the mock KEV fixture; this is not a live exploitation claim.")

        # Invoke LLM contextual synthesis / analysis
        sandbox_artifacts = []
        if validation:
            try:
                arts = validation_repo.list_artifacts(validation.validation_id)
                sandbox_artifacts = [{"type": a.artifact_type, "content": a.content[:300]} for a in arts]
            except EvidenceIntegrityError as exc:
                explanation.append(
                    "LLM context omitted because stored validation evidence failed integrity verification."
                )
                raise ValueError("Stored validation evidence failed integrity verification.") from exc

        llm_analysis = llm_prioritizer.analyze(issue, primary, validation, threat_enrichments)
        if llm_analysis:
            explanation.append(f"AI CONTEXT ({llm_analysis.model_used}): {llm_analysis.contextual_summary}")

        llm_synthesis = llm_prioritizer_service.synthesize_context(
            issue_title=issue.title,
            cwe_primary=primary.vulnerability.cwe_primary or "CWE-Unknown",
            views_dict={"description": primary.vulnerability.description or ""},
            sandbox_verdict=validation.status.value if validation else "not_attempted",
            sandbox_evidence=sandbox_artifacts,
            asset_criticality=asset_crit,
            internet_facing=internet_facing,
            threat_cves=sorted(all_cves),
        )

        if llm_synthesis and "exploitability_assessment" in llm_synthesis:
            explanation.append(f"LLM Contextual Synthesis: {llm_synthesis['exploitability_assessment']}")

        factors = {
            "cvss_score": cvss_score,
            "epss_score": max_epss,
            "kev_flag": kev_flag,
            "asset_criticality": asset_crit,
            "internet_facing": internet_facing,
            "sandbox_validated": bool(validation and validation.status.value == "simulated_match"),
            "cve_ids": sorted(all_cves),
            "validation_status": validation.status.value if validation else "not_attempted",
            "validation_id": validation.validation_id if validation else None,
            "validation_factor": val_norm,
            "contributions": contributions,
            "threat_intelligence": [item.model_dump(mode="json") for item in threat_enrichments],
            "threat_source": "mock",
            "llm_context": llm_synthesis if (llm_synthesis and "evidence_basis" in llm_synthesis) else (llm_analysis.model_dump(mode="json") if llm_analysis else llm_synthesis),
        }

        now_dt = datetime.now(timezone.utc)
        result = PriorityResult(
            priority_id=f"prio-{uuid.uuid4()}",
            canonical_issue_id=canonical_issue_id,
            risk_score=risk_score,
            remediation_tier=tier,
            factors=factors,
            weights_used=weights_used,
            explanation=explanation,
            calculation_version="risk-model-1.0",
            calculated_at=now_dt,
        )

        risk_repo.save_priority(result)
        return result


risk_engine = RiskEngine()
