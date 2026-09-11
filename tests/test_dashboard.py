"""Focused analyst dashboard read-model API checks."""

import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from src.app.database import get_db
from src.app.main import app


def test_dashboard_metrics_is_empty_without_rows():
    with TestClient(app) as client:
        response = client.get("/api/v1/dashboard/metrics")
    assert response.status_code == 200
    assert response.json()["data_status"] == "empty"
    assert response.json()["counts"]["findings"] == 0


def test_case_queue_detail_validation_evidence_and_audit(finding_factory):
    finding = finding_factory()
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO clusters(cluster_id,cluster_method,status,run_at,created_at,updated_at) "
            "VALUES ('cluster-1','fingerprint','candidate',?,?,?)", (now, now, now)
        )
        db.execute(
            "INSERT INTO cluster_members(id,cluster_id,finding_id,role,joined_at,created_at,updated_at) "
            "VALUES ('member-1','cluster-1',?,'primary',?,?,?)",
            (finding.finding_id, now, now, now),
        )
        db.execute(
            "INSERT INTO canonical_issues(canonical_issue_id,title,cluster_id,source_finding_ids,"
            "source_scanners,merge_method,merge_reason,created_at,updated_at) "
            "VALUES ('issue-1','SQL Injection','cluster-1',?,?,?,?,?,?)",
            (json.dumps([finding.finding_id]), json.dumps(["burp"]), "fingerprint", "[]", now, now),
        )
        db.execute(
            "INSERT INTO cases(case_id,canonical_issue_id,status,title,summary,case_data,created_at,last_updated_at,updated_at) "
            "VALUES ('case-1','issue-1','pending_review','SQL Injection case','summary','{}',?,?,?)",
            (now, now, now),
        )
        db.execute(
            "INSERT INTO audit_events(event_id,entity_type,entity_id,action,actor,details,occurred_at,created_at) "
            "VALUES ('event-1','case','case-1','created','system','{}',?,?)", (now, now)
        )

    with TestClient(app) as client:
        queue = client.get("/api/v1/dashboard/case-queue")
        detail = client.get("/api/v1/dashboard/cases/case-1")
        audit = client.get("/api/v1/dashboard/cases/case-1/audit")
        cluster = client.get("/api/v1/dashboard/clusters/cluster-1")
        assert queue.status_code == 200 and queue.json()["cases"][0]["case_id"] == "case-1"
        assert detail.status_code == 200
        assert detail.json()["findings"][0]["finding_id"] == finding.finding_id
        assert detail.json()["validations"] == []
        assert audit.json()["events"][0]["action"] == "created"
        assert cluster.json()["members"][0]["finding_id"] == finding.finding_id
        assert client.get("/api/v1/dashboard/cases/missing").status_code == 404
