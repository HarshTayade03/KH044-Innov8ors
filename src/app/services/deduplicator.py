"""Deterministic, pairwise-safe deduplication and atomic analyst decisions.

Contract: docs/MODULE_SPECS/R0_baseline.md.
"""
import uuid
from datetime import datetime, timezone
from itertools import combinations
from urllib.parse import urlsplit

try:
    import numpy as np
    from sklearn.cluster import HDBSCAN
    HAS_SKLEARN = True
except ImportError:
    np = HDBSCAN = None
    HAS_SKLEARN = False

from src.app.schemas.dedup import (
    Cluster, ClusterMember, CanonicalIssue, ClusterMethod, ClusterStatus,
    ReviewStatus, DedupRunSummary,
)
from src.app.repositories.findings_repo import repo as findings_repo
from src.app.repositories.dedup_repo import dedup_repo
from src.app.services.extractor import extractor_service
from src.app.services.embedding import embedding_service, weighted_similarity


def stable_id(kind, member_ids):
    import json
    key = json.dumps(sorted(member_ids), separators=(',', ':'))
    return f'{kind}-{uuid.uuid5(uuid.NAMESPACE_URL, kind + key)}'


class DedupConflict(ValueError):
    pass


class DeduplicationEngine:
    @staticmethod
    def _host(value):
        if not value:
            return None
        parsed = urlsplit(value if '://' in value else '//' + value)
        return (parsed.hostname or value).lower().rstrip('.')

    def _check_hard_blocks(self, first, second):
        for a, b in ((first.asset.asset_name, second.asset.asset_name),
                     (first.location.host or first.location.url,
                      second.location.host or second.location.url)):
            a, b = self._host(a), self._host(b)
            if a and b and a != 'unknown' and b != 'unknown' and a != b:
                return True
        # Package coordinates and parameter names can be case-sensitive.
        for field in ('package', 'parameter'):
            a, b = getattr(first.location, field), getattr(second.location, field)
            if a and b and a != b:
                return True
        return False

    def _safe_groups(self, findings):
        groups = []
        for finding in sorted(findings, key=lambda f: f.finding_id):
            for group in groups:
                if all(not self._check_hard_blocks(finding, other) for other in group):
                    group.append(finding)
                    break
            else:
                groups.append([finding])
        return groups

    def _cluster(self, findings, method, similarity=1.0):
        findings = sorted(findings, key=lambda f: f.finding_id)
        now = datetime.now(timezone.utc)
        cid = stable_id('cluster-' + method.value, [f.finding_id for f in findings])
        return Cluster(
            cluster_id=cid, cluster_method=method,
            status=ClusterStatus.MERGED if method == ClusterMethod.FINGERPRINT else ClusterStatus.CANDIDATE,
            similarity_score=similarity, merge_confidence=similarity,
            merge_reason=['Exact fingerprint with pairwise hard-block checks'] if method == ClusterMethod.FINGERPRINT
                         else ['HDBSCAN candidate with pairwise hard-block checks'],
            hdbscan_params={'min_cluster_size': 2, 'metric': 'precomputed'} if method == ClusterMethod.SEMANTIC else None,
            members=[ClusterMember(id=stable_id('cm', [cid, f.finding_id]), cluster_id=cid,
                                   finding_id=f.finding_id, role='primary' if i == 0 else 'secondary',
                                   joined_at=now) for i, f in enumerate(findings)],
            run_at=now, created_at=now, updated_at=now,
        )

    def stage_a_fingerprint_dedup(self, findings):
        buckets = {}
        for finding in findings:
            buckets.setdefault(finding.fingerprint, []).append(finding)
        clusters, remaining = [], []
        for key in sorted(buckets):
            for group in self._safe_groups(buckets[key]):
                if len(group) > 1:
                    clusters.append(self._cluster(group, ClusterMethod.FINGERPRINT))
                else:
                    remaining.extend(group)
        return clusters, remaining

    def stage_b_semantic_clustering(self, findings, report=None):
        report = report if report is not None else {}
        report.update(semantic_status='not_needed', embedding_models=[], warnings=[])
        if len(findings) < 2:
            return []
        if not HAS_SKLEARN:
            report.update(semantic_status='unavailable', warnings=['scikit-learn unavailable; semantic stage skipped'])
            return []
        # Generate with the current backend: old vectors may be incorrectly labeled or stale.
        views = []
        for finding in sorted(findings, key=lambda f: f.finding_id):
            view = extractor_service.extract_views(finding)
            findings_repo.save_finding_views(view)
            views.append(view)
        embeddings = embedding_service.generate_batch_embeddings(views)
        by_model, by_id = {}, {f.finding_id: f for f in findings}
        for emb in embeddings:
            findings_repo.save_finding_embeddings(emb)
            if emb.combined_embedding:
                key = (emb.embedding_model, emb.model_version, emb.embedding_dimension)
                by_model.setdefault(key, []).append((by_id[emb.finding_id], emb))
        report['embedding_models'] = sorted({key[0] for key in by_model})
        if any(name.startswith('sha256-') for name in report['embedding_models']):
            report['warnings'].append('Hashing fallback used; similarity is lexical, not learned semantic evidence')
        clusters = []
        report['semantic_status'] = 'completed'
        for pairs in by_model.values():
            if len(pairs) < 2:
                continue
            distances = np.zeros((len(pairs), len(pairs)), dtype=np.float64)
            for i, j in combinations(range(len(pairs)), 2):
                a, ea = pairs[i]
                b, eb = pairs[j]
                sim = 0.0 if self._check_hard_blocks(a, b) else weighted_similarity(ea, eb)
                distances[i, j] = distances[j, i] = max(0.0, min(2.0, 1.0 - sim))
            try:
                labels = HDBSCAN(min_cluster_size=2, metric='precomputed', allow_single_cluster=True).fit_predict(distances)
            except (ValueError, RuntimeError) as exc:
                # Numerical/model errors must be visible to callers, not silent success.
                report['semantic_status'] = 'failed'
                report['warnings'].append(f'HDBSCAN failed: {exc}')
                continue
            groups = {}
            for index, label in enumerate(labels):
                if label != -1:
                    groups.setdefault(int(label), []).append(pairs[index][0])
            index_by_id = {f.finding_id: i for i, (f, _) in enumerate(pairs)}
            for candidate in groups.values():
                for group in self._safe_groups(candidate):
                    if len(group) < 2:
                        continue
                    sims = [1.0 - distances[index_by_id[a.finding_id], index_by_id[b.finding_id]]
                            for a, b in combinations(group, 2)]
                    clusters.append(self._cluster(group, ClusterMethod.SEMANTIC, round(float(np.mean(sims)), 4)))
        return clusters

    def create_canonical_issues(self, findings, clusters):
        by_id = {f.finding_id: f for f in findings}
        represented, issues = set(), []
        now = datetime.now(timezone.utc)
        for cluster in clusters:
            ids = sorted(m.finding_id for m in cluster.members)
            if not ids or any(fid not in by_id for fid in ids) or represented.intersection(ids):
                raise DedupConflict('Invalid or overlapping cluster membership')
            members = [by_id[fid] for fid in ids]
            if any(self._check_hard_blocks(a, b) for a, b in combinations(members, 2)):
                raise DedupConflict('Cluster violates hard-block rules')
            represented.update(ids)
            issues.append(CanonicalIssue(
                canonical_issue_id=stable_id('issue', ids), title=f'{members[0].vulnerability.title} ({len(ids)} scanner reports)',
                cluster_id=cluster.cluster_id, source_finding_ids=ids,
                source_scanners=sorted({f.source_scanner for f in members}), merge_method=cluster.cluster_method,
                merge_confidence=cluster.merge_confidence if cluster.merge_confidence is not None else 1.0,
                merge_reason=cluster.merge_reason, created_at=now, updated_at=now,
            ))
        for finding in sorted(findings, key=lambda f: f.finding_id):
            if finding.finding_id not in represented:
                issues.append(CanonicalIssue(
                    canonical_issue_id=stable_id('issue', [finding.finding_id]), title=finding.vulnerability.title,
                    source_finding_ids=[finding.finding_id], source_scanners=[finding.source_scanner],
                    merge_method=ClusterMethod.FINGERPRINT, merge_reason=['Singleton finding'],
                    created_at=now, updated_at=now,
                ))
        return issues

    def run_deduplication(self):
        with dedup_repo.transaction():
            findings = findings_repo.list_normalized_findings(limit=-1)
            existing = dedup_repo.list_canonical_issues(limit=-1)
            fixed = [i for i in existing if i.review_status in (ReviewStatus.KEPT_SEPARATE, ReviewStatus.MERGED)]
            by_id = {f.finding_id: f for f in findings}
            for issue in fixed:
                if any(fid not in by_id for fid in issue.source_finding_ids):
                    raise DedupConflict('Reviewed issue has missing findings')
                members = [by_id[fid] for fid in issue.source_finding_ids]
                if any(self._check_hard_blocks(a, b) for a, b in combinations(members, 2)):
                    raise DedupConflict('Legacy reviewed issue violates hard-block rules; split it first')
            reserved = {fid for i in fixed for fid in i.source_finding_ids}
            remaining = [f for f in findings if f.finding_id not in reserved]
            deterministic, unclustered = self.stage_a_fingerprint_dedup(remaining)
            report = {}
            semantic = self.stage_b_semantic_clustering(unclustered, report)
            clusters = deterministic + semantic
            issues = self.create_canonical_issues(remaining, clusters) + fixed
            # Fail before publishing if legacy reviewed issues already overlap.
            ids = [fid for i in issues for fid in i.source_finding_ids]
            if len(ids) != len(set(ids)):
                raise DedupConflict('Overlapping reviewed issues require manual reconciliation')
            dedup_repo.reconcile(clusters, issues)
            return DedupRunSummary(
                run_id=str(uuid.uuid4()), total_findings_processed=len(findings),
                deterministic_clusters_created=len(deterministic), semantic_clusters_created=len(semantic),
                total_canonical_issues=len(issues), run_at=datetime.now(timezone.utc), **report,
            )

    def review_cluster(self, cluster_id, merge):
        with dedup_repo.transaction():
            cluster = dedup_repo.get_cluster(cluster_id)
            if not cluster:
                raise LookupError('Cluster not found')
            members = [findings_repo.get_normalized_finding(m.finding_id) for m in cluster.members]
            if not members or any(f is None for f in members):
                raise DedupConflict('Cluster has missing source findings')
            member_ids = {f.finding_id for f in members}
            active = dedup_repo.list_canonical_issues(limit=-1)
            affected = [i for i in active if member_ids.intersection(i.source_finding_ids)]
            if any(not set(i.source_finding_ids).issubset(member_ids) for i in affected):
                raise DedupConflict('Cluster overlaps another active issue; review its current cluster instead')
            replacement = self.create_canonical_issues(members, [cluster] if merge else [])
            for issue in replacement:
                issue.review_status = ReviewStatus.MERGED if merge else ReviewStatus.KEPT_SEPARATE
                if not merge:
                    issue.merge_method = ClusterMethod.MANUAL
                    issue.merge_reason = ['Kept separate by analyst from cluster ' + cluster_id]
            target = ClusterStatus.MERGED if merge else ClusterStatus.REJECTED_MERGE
            same = {i.canonical_issue_id for i in affected} == {i.canonical_issue_id for i in replacement}
            if cluster.status != target or not same or any(i.review_status != replacement[0].review_status for i in affected):
                cluster.status = target
                cluster.updated_at = datetime.now(timezone.utc)
                others = [i for i in active if i not in affected]
                dedup_repo.reconcile([cluster], others + replacement, actor='analyst')
                dedup_repo.audit('cluster', cluster_id, 'merge' if merge else 'split', 'analyst',
                                 {'canonical_issue_ids': [i.canonical_issue_id for i in replacement]})
            result = {'status': 'success', 'cluster_id': cluster_id, 'cluster_status': target.value}
            if not merge:
                result['new_canonical_issues'] = sorted(i.canonical_issue_id for i in replacement)
            return result


deduplicator_service = DeduplicationEngine()
