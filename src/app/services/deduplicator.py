"""
services/deduplicator.py — Two-stage deduplication engine (Stage A: Fingerprint, Stage B: HDBSCAN/Semantic).

Defined according to docs/MODULE_SPECS/M3_deduplication.md.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Any

# Optional ML dependencies for Stage B semantic clustering
try:
    import numpy as np
    from sklearn.cluster import HDBSCAN
    HAS_SKLEARN = True
except ImportError:
    np = None
    HDBSCAN = None
    HAS_SKLEARN = False

from src.app.schemas.canonical import NormalizedFinding
from src.app.schemas.dedup import (
    Cluster, ClusterMember, CanonicalIssue, ClusterMethod, ClusterStatus,
    ReviewStatus, DedupRunSummary
)
from src.app.schemas.views import FindingEmbeddings
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.services.extractor import extractor_service
from src.app.services.embedding import embedding_service, cosine_similarity, weighted_similarity


class DeduplicationEngine:
    """Orchestrates Stage A (Fingerprint) and Stage B (Semantic) deduplication."""

    def _check_hard_blocks(self, f1: NormalizedFinding, f2: NormalizedFinding) -> bool:
        """
        Returns True if a hard block prevents merging f1 and f2.
        """
        # Hard Block 1: Cross-asset merge block
        if f1.asset.asset_name and f2.asset.asset_name:
            if f1.asset.asset_name != f2.asset.asset_name and f1.asset.asset_name != "unknown" and f2.asset.asset_name != "unknown":
                return True

        # Hard Block 2: Cross-package merge block (SCA)
        p1, p2 = f1.location.package, f2.location.package
        if p1 and p2 and p1.lower() != p2.lower():
            return True

        # Hard Block 3: Explicit different parameter block
        param1, param2 = f1.location.parameter, f2.location.parameter
        if param1 and param2 and param1.lower() != param2.lower():
            # Allow merge if both parameter classes are generic or missing
            return True

        return False

    def stage_a_fingerprint_dedup(
        self, findings: list[NormalizedFinding]
    ) -> tuple[list[Cluster], list[NormalizedFinding]]:
        """
        Stage A: Group findings by exact SHA-256 fingerprint.
        """
        fp_groups: dict[str, list[NormalizedFinding]] = {}
        for f in findings:
            fp_groups.setdefault(f.fingerprint, []).append(f)

        clusters: list[Cluster] = []
        unclustered: list[NormalizedFinding] = []
        now_dt = datetime.now(timezone.utc)

        for fp, group in fp_groups.items():
            if len(group) > 1:
                c_id = f"cluster-fp-{uuid.uuid4()}"
                members = [
                    ClusterMember(
                        id=f"cm-{uuid.uuid4()}",
                        cluster_id=c_id,
                        finding_id=f.finding_id,
                        role="primary" if idx == 0 else "secondary",
                        joined_at=now_dt,
                    )
                    for idx, f in enumerate(group)
                ]
                cluster = Cluster(
                    cluster_id=c_id,
                    cluster_method=ClusterMethod.FINGERPRINT,
                    status=ClusterStatus.MERGED,
                    similarity_score=1.0,
                    merge_reason=["Exact fingerprint match (cwe_root + canonical_path + parameter_class)"],
                    merge_confidence=1.0,
                    hdbscan_params=None,
                    members=members,
                    run_at=now_dt,
                    created_at=now_dt,
                    updated_at=now_dt,
                )
                clusters.append(cluster)
            else:
                unclustered.append(group[0])

        return clusters, unclustered

    def stage_b_semantic_clustering(
        self, unclustered_findings: list[NormalizedFinding]
    ) -> list[Cluster]:
        """
        Stage B: HDBSCAN semantic clustering on remaining findings.
        """
        if not HAS_SKLEARN or len(unclustered_findings) < 2:
            return []

        # Load or generate embeddings for each finding
        finding_embeddings_list: list[tuple[NormalizedFinding, FindingEmbeddings]] = []
        for f in unclustered_findings:
            emb = findings_repo.get_finding_embeddings(f.finding_id)
            if not emb or not emb.combined_embedding:
                views = findings_repo.get_finding_views(f.finding_id)
                if not views:
                    views = extractor_service.extract_views(f)
                    findings_repo.save_finding_views(views)
                emb = embedding_service.generate_embeddings(views)
                findings_repo.save_finding_embeddings(emb)
            if emb and emb.combined_embedding:
                finding_embeddings_list.append((f, emb))

        if len(finding_embeddings_list) < 2:
            return []

        n = len(finding_embeddings_list)
        dist_matrix = np.zeros((n, n), dtype=np.float32)

        for i in range(n):
            f1, emb1 = finding_embeddings_list[i]
            for j in range(i + 1, n):
                f2, emb2 = finding_embeddings_list[j]
                if self._check_hard_blocks(f1, f2):
                    sim = 0.0
                else:
                    sim = weighted_similarity(emb1, emb2)
                dist = max(0.0, 1.0 - sim)
                dist_matrix[i, j] = dist
                dist_matrix[j, i] = dist

        now_dt = datetime.now(timezone.utc)
        clusters: list[Cluster] = []

        try:
            # Fit HDBSCAN with precomputed distance matrix
            clusterer = HDBSCAN(min_cluster_size=2, metric="precomputed", allow_single_cluster=True)
            labels = clusterer.fit_predict(dist_matrix)

            label_groups: dict[int, list[int]] = {}
            for idx, label in enumerate(labels):
                if label != -1:
                    label_groups.setdefault(int(label), []).append(idx)

            for label, indices in label_groups.items():
                if len(indices) > 1:
                    c_id = f"cluster-sem-{uuid.uuid4()}"
                    members = []
                    sub_matrix_sims = []
                    for idx_pos, idx_val in enumerate(indices):
                        f, _ = finding_embeddings_list[idx_val]
                        members.append(
                            ClusterMember(
                                id=f"cm-{uuid.uuid4()}",
                                cluster_id=c_id,
                                finding_id=f.finding_id,
                                role="primary" if idx_pos == 0 else "secondary",
                                joined_at=now_dt,
                            )
                        )
                        for other_val in indices[idx_pos + 1:]:
                            sub_matrix_sims.append(1.0 - dist_matrix[idx_val, other_val])

                    avg_sim = float(np.mean(sub_matrix_sims)) if sub_matrix_sims else 0.85
                    cluster = Cluster(
                        cluster_id=c_id,
                        cluster_method=ClusterMethod.SEMANTIC,
                        status=ClusterStatus.CANDIDATE,
                        similarity_score=round(avg_sim, 4),
                        merge_reason=[
                            f"Semantic vector similarity score: {round(avg_sim, 2)}",
                            "HDBSCAN density-based cluster",
                        ],
                        merge_confidence=round(avg_sim, 2),
                        hdbscan_params={"min_cluster_size": 2, "metric": "precomputed"},
                        members=members,
                        run_at=now_dt,
                        created_at=now_dt,
                        updated_at=now_dt,
                    )
                    clusters.append(cluster)
        except Exception as e:
            print(f"[dedup] HDBSCAN clustering fallback: {e}")

        return clusters

    def create_canonical_issues(
        self,
        all_findings: list[NormalizedFinding],
        clusters: list[Cluster],
    ) -> list[CanonicalIssue]:
        """
        Creates CanonicalIssue objects from all clusters and remaining singleton findings.
        """
        finding_map = {f.finding_id: f for f in all_findings}
        clustered_finding_ids: set[str] = set()
        canonical_issues: list[CanonicalIssue] = []
        now_dt = datetime.now(timezone.utc)

        # 1. Create issues from clusters
        for cluster in clusters:
            member_ids = [m.finding_id for m in cluster.members]
            clustered_finding_ids.update(member_ids)
            member_findings = [finding_map[fid] for fid in member_ids if fid in finding_map]

            if not member_findings:
                continue

            primary_finding = member_findings[0]
            scanners = list({f.source_scanner for f in member_findings})

            title = primary_finding.vulnerability.title
            if len(member_findings) > 1:
                title = f"{title} ({len(member_findings)} scanner reports)"

            issue = CanonicalIssue(
                canonical_issue_id=f"issue-{uuid.uuid4()}",
                title=title,
                cluster_id=cluster.cluster_id,
                source_finding_ids=member_ids,
                source_scanners=scanners,
                merge_method=cluster.cluster_method,
                merge_confidence=cluster.merge_confidence or 1.0,
                merge_reason=cluster.merge_reason,
                review_status=ReviewStatus.PENDING,
                created_at=now_dt,
                updated_at=now_dt,
            )
            canonical_issues.append(issue)

        # 2. Create singleton issues for unclustered findings
        for f in all_findings:
            if f.finding_id not in clustered_finding_ids:
                issue = CanonicalIssue(
                    canonical_issue_id=f"issue-{uuid.uuid4()}",
                    title=f.vulnerability.title,
                    cluster_id=None,
                    source_finding_ids=[f.finding_id],
                    source_scanners=[f.source_scanner],
                    merge_method=ClusterMethod.FINGERPRINT,
                    merge_confidence=1.0,
                    merge_reason=["Singleton finding (unique fingerprint and vector)"],
                    review_status=ReviewStatus.PENDING,
                    created_at=now_dt,
                    updated_at=now_dt,
                )
                canonical_issues.append(issue)

        return canonical_issues

    def run_deduplication(self) -> DedupRunSummary:
        """
        Runs full two-stage deduplication over all normalized findings in the DB.
        """
        all_findings = findings_repo.list_normalized_findings(limit=1000)
        if not all_findings:
            now_dt = datetime.now(timezone.utc)
            return DedupRunSummary(
                run_id=f"run-{uuid.uuid4()}",
                total_findings_processed=0,
                deterministic_clusters_created=0,
                semantic_clusters_created=0,
                total_canonical_issues=0,
                run_at=now_dt,
            )

        # Stage A
        stage_a_clusters, unclustered = self.stage_a_fingerprint_dedup(all_findings)

        # Stage B
        stage_b_clusters = self.stage_b_semantic_clustering(unclustered)

        all_clusters = stage_a_clusters + stage_b_clusters

        # Save clusters to DB
        for c in all_clusters:
            dedup_repo.save_cluster(c)

        # Create & save canonical issues to DB
        canonical_issues = self.create_canonical_issues(all_findings, all_clusters)
        for issue in canonical_issues:
            dedup_repo.save_canonical_issue(issue)

        now_dt = datetime.now(timezone.utc)
        return DedupRunSummary(
            run_id=f"run-{uuid.uuid4()}",
            total_findings_processed=len(all_findings),
            deterministic_clusters_created=len(stage_a_clusters),
            semantic_clusters_created=len(stage_b_clusters),
            total_canonical_issues=len(canonical_issues),
            run_at=now_dt,
        )


deduplicator_service = DeduplicationEngine()
