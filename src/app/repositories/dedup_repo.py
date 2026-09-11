"""
repositories/dedup_repo.py — Database repository operations for clusters, members, and canonical issues.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from src.app.database import get_db
from src.app.schemas.dedup import Cluster, ClusterMember, CanonicalIssue, ClusterMethod, ClusterStatus, ReviewStatus


class DedupRepository:
    """Repository for managing clusters and canonical issues."""

    def save_cluster(self, cluster: Cluster) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        with get_db() as db:
            db.execute(
                """
                INSERT INTO clusters (
                    cluster_id, cluster_method, status, similarity_score, merge_reason,
                    merge_confidence, hdbscan_params, run_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cluster_id) DO UPDATE SET
                    status=excluded.status,
                    similarity_score=excluded.similarity_score,
                    merge_reason=excluded.merge_reason,
                    merge_confidence=excluded.merge_confidence,
                    hdbscan_params=excluded.hdbscan_params,
                    updated_at=excluded.updated_at
                """,
                (
                    cluster.cluster_id,
                    cluster.cluster_method.value,
                    cluster.status.value,
                    cluster.similarity_score,
                    json.dumps(cluster.merge_reason),
                    cluster.merge_confidence,
                    json.dumps(cluster.hdbscan_params) if cluster.hdbscan_params else None,
                    cluster.run_at.isoformat(),
                    cluster.created_at.isoformat(),
                    now_str,
                ),
            )

            # Insert cluster members
            for member in cluster.members:
                db.execute(
                    """
                    INSERT INTO cluster_members (
                        id, cluster_id, finding_id, role, joined_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cluster_id, finding_id) DO UPDATE SET
                        role=excluded.role,
                        updated_at=excluded.updated_at
                    """,
                    (
                        member.id or f"cm-{uuid.uuid4()}",
                        cluster.cluster_id,
                        member.finding_id,
                        member.role,
                        member.joined_at.isoformat(),
                        now_str,
                        now_str,
                    ),
                )

    def get_cluster(self, cluster_id: str) -> Optional[Cluster]:
        with get_db() as db:
            row = db.execute("SELECT * FROM clusters WHERE cluster_id = ?", (cluster_id,)).fetchone()
            if not row:
                return None

            members_rows = db.execute(
                "SELECT * FROM cluster_members WHERE cluster_id = ?", (cluster_id,)
            ).fetchall()

        members = [
            ClusterMember(
                id=mr["id"],
                cluster_id=mr["cluster_id"],
                finding_id=mr["finding_id"],
                role=mr["role"],
                joined_at=datetime.fromisoformat(mr["joined_at"]),
            )
            for mr in members_rows
        ]

        return Cluster(
            cluster_id=row["cluster_id"],
            cluster_method=ClusterMethod(row["cluster_method"]),
            status=ClusterStatus(row["status"]),
            similarity_score=row["similarity_score"],
            merge_reason=json.loads(row["merge_reason"]) if row["merge_reason"] else [],
            merge_confidence=row["merge_confidence"],
            hdbscan_params=json.loads(row["hdbscan_params"]) if row["hdbscan_params"] else None,
            members=members,
            run_at=datetime.fromisoformat(row["run_at"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_clusters(self, limit: int = 100, offset: int = 0) -> list[Cluster]:
        with get_db() as db:
            rows = db.execute(
                "SELECT cluster_id FROM clusters ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

        clusters = []
        for r in rows:
            c = self.get_cluster(r["cluster_id"])
            if c:
                clusters.append(c)
        return clusters

    def save_canonical_issue(self, issue: CanonicalIssue) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        with get_db() as db:
            db.execute(
                """
                INSERT INTO canonical_issues (
                    canonical_issue_id, title, cluster_id, source_finding_ids,
                    source_scanners, merge_method, merge_confidence, merge_reason,
                    review_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(canonical_issue_id) DO UPDATE SET
                    title=excluded.title,
                    source_finding_ids=excluded.source_finding_ids,
                    source_scanners=excluded.source_scanners,
                    review_status=excluded.review_status,
                    updated_at=excluded.updated_at
                """,
                (
                    issue.canonical_issue_id,
                    issue.title,
                    issue.cluster_id,
                    json.dumps(issue.source_finding_ids),
                    json.dumps(issue.source_scanners),
                    issue.merge_method.value,
                    issue.merge_confidence,
                    json.dumps(issue.merge_reason),
                    issue.review_status.value,
                    issue.created_at.isoformat(),
                    now_str,
                ),
            )

    def get_canonical_issue(self, canonical_issue_id: str) -> Optional[CanonicalIssue]:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM canonical_issues WHERE canonical_issue_id = ?",
                (canonical_issue_id,),
            ).fetchone()

        if not row:
            return None

        return CanonicalIssue(
            canonical_issue_id=row["canonical_issue_id"],
            title=row["title"],
            cluster_id=row["cluster_id"],
            source_finding_ids=json.loads(row["source_finding_ids"]),
            source_scanners=json.loads(row["source_scanners"]),
            merge_method=ClusterMethod(row["merge_method"]),
            merge_confidence=row["merge_confidence"],
            merge_reason=json.loads(row["merge_reason"]),
            review_status=ReviewStatus(row["review_status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_canonical_issues(self, limit: int = 100, offset: int = 0) -> list[CanonicalIssue]:
        with get_db() as db:
            rows = db.execute(
                "SELECT canonical_issue_id FROM canonical_issues ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

        issues = []
        for r in rows:
            ci = self.get_canonical_issue(r["canonical_issue_id"])
            if ci:
                issues.append(ci)
        return issues


dedup_repo = DedupRepository()
