from datetime import datetime, timezone

import pytest

from src.app.repositories.case_repo import case_repo
from src.app.schemas.case import Case, CaseStatus, ReviewAction
from src.app.services.case_service import CaseError, CaseValidationError, case_service


def _case():
    now = datetime.now(timezone.utc)
    return Case(case_id="case-1", canonical_issue_id="issue-1", title="Test issue",
                case_data={"priority": None}, created_at=now, last_updated_at=now)


def test_review_requires_reason_and_records_audit():
    case_repo.save_snapshot(_case())
    with pytest.raises(CaseValidationError):
        case_service.review("case-1", "approved", ReviewAction(actor_id="analyst", reason=" "))

    result = case_service.review("case-1", "approved",
                                 ReviewAction(actor_id="analyst", reason="confirmed evidence"))
    assert result.status == CaseStatus.APPROVED
    assert result.reviews[0].actor_id == "analyst"
    assert result.audit_events[0].action == "approved"


def test_terminal_decision_cannot_repeat():
    case_repo.save_snapshot(_case())
    case_service.review("case-1", "rejected", ReviewAction(actor_id="a", reason="duplicate"))
    with pytest.raises(CaseError, match="Terminal"):
        case_service.review("case-1", "approved", ReviewAction(actor_id="b", reason="changed"))
