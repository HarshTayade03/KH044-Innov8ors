"""
API router for AI Auto-Remediation and Patch Generation endpoints.
"""

from fastapi import APIRouter, HTTPException
from src.app.repositories.dedup_repo import dedup_repo
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.schemas.remediation import RemediationPatchRequest, RemediationPatchResponse
from src.app.services.extractor import extractor_service
from src.app.services.patch_generator import PatchGeneratorService

router = APIRouter(tags=["Remediation"])
patch_service = PatchGeneratorService()


@router.post("/canonical-issues/{canonical_issue_id}/remediation-patch", response_model=RemediationPatchResponse)
async def generate_remediation_patch(canonical_issue_id: str, request: RemediationPatchRequest | None = None):
    """
    Generate an AI-driven security patch and git unified diff for a canonical issue.
    """
    target_lang = request.target_language if request else "python"

    issue = dedup_repo.get_canonical_issue(canonical_issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail=f"Canonical issue '{canonical_issue_id}' not found.")

    # Get sample finding for view extraction
    findings = findings_repo.get_many(issue.finding_ids) if hasattr(issue, "finding_ids") and issue.finding_ids else []
    sample_finding = findings[0] if findings else None

    cwe_primary = "CWE-OTHER"
    loc_view = None
    repro_view = None
    impact_view = None
    desc_view = None

    if sample_finding:
        cwe_primary = sample_finding.vulnerability.cwe_primary if hasattr(sample_finding, "vulnerability") and sample_finding.vulnerability else "CWE-OTHER"
        try:
            views = extractor_service.extract_views(sample_finding)
            loc_view = views.location.text if views.location else None
            repro_view = views.reproduction.text if views.reproduction else None
            impact_view = views.impact.text if views.impact else None
            desc_view = views.description.text if views.description else None
        except Exception:
            pass

    return patch_service.generate_patch(
        canonical_issue_id=canonical_issue_id,
        title=issue.title or "Vulnerability Finding",
        cwe_primary=cwe_primary,
        location_view=loc_view or "Unknown location",
        reproduction_view=repro_view,
        impact_view=impact_view,
        description_view=desc_view,
        target_language=target_lang,
    )
