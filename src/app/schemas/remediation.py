"""
Pydantic schemas for AI Auto-Remediation and Patch Generation.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class PatchValidation(BaseModel):
    """Syntax and sanity validation details for a generated patch."""
    is_valid_syntax: bool = Field(..., description="True if generated code passes syntax validation")
    language: str = Field("python", description="Target programming language for the patch")
    validation_error: Optional[str] = Field(None, description="Syntax error message if validation failed")
    safety_checks_passed: bool = Field(True, description="True if no hardcoded credentials or dangerous constructs detected")


class RemediationPatchResponse(BaseModel):
    """Response DTO containing AI-generated code remediation patch."""
    canonical_issue_id: str = Field(..., description="Canonical issue ID patched")
    cwe_id: str = Field(..., description="Primary CWE identifier")
    title: str = Field(..., description="Short patch title")
    summary: str = Field(..., description="Human-readable explanation of why this patch fixes the vulnerability")
    git_diff: str = Field(..., description="Unified git diff string proposing code changes")
    vulnerable_code_snippet: str = Field(..., description="Original vulnerable code snippet")
    fixed_code_snippet: str = Field(..., description="Recommended fixed code snippet")
    validation: PatchValidation = Field(..., description="Syntax and safety validation result")
    provider_used: str = Field("ai_remediator", description="LLM provider or rule fallback engine used")
    confidence: float = Field(0.9, ge=0.0, le=1.0, description="Confidence score for the patch")


class RemediationPatchRequest(BaseModel):
    """Request DTO to trigger AI remediation patch generation."""
    target_language: str = Field("python", description="Target language (python, javascript, sql, html)")
    additional_context: Optional[str] = Field(None, description="Optional extra repository or framework context")
