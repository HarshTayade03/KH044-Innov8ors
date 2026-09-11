"""
repositories/findings_repo.py — All database read/write operations for findings.

Architecture rule: NO module talks to SQLite directly except this repository file.
All persistence operations are centralized here.
"""

import json
from datetime import datetime, timezone
from typing import Optional, Any
from src.app.database import get_db
from src.app.schemas.canonical import NormalizedFinding


class FindingsRepository:
    """Central data access layer. All modules use this to read/write the database."""

    def save_scanner_finding(
        self,
        finding_id: str,
        source_scanner: str,
        source_finding_id: Optional[str],
        ingestion_batch_id: str,
        raw_data: dict[str, Any],
        raw_data_hash: str,
        status: str = "received",
    ) -> None:
        """Save unmodified raw scanner finding to scanner_findings table."""
        now_str = datetime.now(timezone.utc).isoformat()
        raw_json = json.dumps(raw_data, default=str)
        with get_db() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO scanner_findings (
                    finding_id, source_scanner, source_finding_id, ingestion_batch_id,
                    raw_data, raw_data_hash, status, ingested_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    source_scanner,
                    source_finding_id,
                    ingestion_batch_id,
                    raw_json,
                    raw_data_hash,
                    status,
                    now_str,
                    now_str,
                    now_str,
                ),
            )

    def save_normalized_finding(self, finding: NormalizedFinding) -> None:
        """Save canonical NormalizedFinding to normalized_findings table."""
        now_str = datetime.now(timezone.utc).isoformat()
        data_json = finding.model_dump_json()
        warnings_json = json.dumps(finding.quality.warnings)
        errors_json = json.dumps(finding.quality.errors)

        with get_db() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO normalized_findings (
                    finding_id, fingerprint, normalization_status, completeness_score,
                    normalization_warnings, normalization_errors, normalized_data,
                    normalized_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    finding.fingerprint,
                    finding.quality.normalization_status,
                    finding.quality.completeness_score,
                    warnings_json,
                    errors_json,
                    data_json,
                    now_str,
                    now_str,
                    now_str,
                ),
            )
            # Also update scanner_findings status
            db.execute(
                "UPDATE scanner_findings SET status = ?, updated_at = ? WHERE finding_id = ?",
                (finding.quality.normalization_status, now_str, finding.finding_id),
            )

    def get_normalized_finding(self, finding_id: str) -> Optional[NormalizedFinding]:
        """Fetch a single canonical NormalizedFinding by ID."""
        with get_db() as db:
            row = db.execute(
                "SELECT normalized_data FROM normalized_findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()

        if not row:
            return None
        return NormalizedFinding.model_validate_json(row["normalized_data"])

    def list_normalized_findings(self, limit: int = 100, offset: int = 0) -> list[NormalizedFinding]:
        """List canonical NormalizedFindings with pagination."""
        with get_db() as db:
            rows = db.execute(
                "SELECT normalized_data FROM normalized_findings ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

        return [NormalizedFinding.model_validate_json(r["normalized_data"]) for r in rows]

    def count_normalized_findings(self) -> int:
        """Return total count of normalized findings."""
        with get_db() as db:
            row = db.execute("SELECT COUNT(*) as cnt FROM normalized_findings").fetchone()
        return row["cnt"] if row else 0

    def save_finding_views(self, views: "FindingViews") -> None:
        """Save FindingViews object to finding_views table."""
        import uuid
        from src.app.schemas.views import FindingViews, SingleView
        now_str = datetime.now(timezone.utc).isoformat()

        view_map = {
            "description": views.description,
            "location": views.location,
            "reproduction": views.reproduction,
            "impact": views.impact,
        }

        with get_db() as db:
            for view_type, single_view in view_map.items():
                db.execute(
                    """
                    INSERT INTO finding_views (
                        id, finding_id, view_type, view_text, view_structured,
                        view_status, confidence, extraction_method, source_fields,
                        warnings, extracted_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id, view_type) DO UPDATE SET
                        view_text=excluded.view_text,
                        view_structured=excluded.view_structured,
                        view_status=excluded.view_status,
                        confidence=excluded.confidence,
                        extraction_method=excluded.extraction_method,
                        source_fields=excluded.source_fields,
                        warnings=excluded.warnings,
                        extracted_at=excluded.extracted_at,
                        updated_at=excluded.updated_at
                    """,
                    (
                        f"view-{uuid.uuid4()}",
                        views.finding_id,
                        view_type,
                        single_view.text,
                        json.dumps(single_view.structured, default=str),
                        single_view.status.value,
                        single_view.confidence,
                        single_view.extraction_method,
                        json.dumps(single_view.source_fields),
                        json.dumps(single_view.warnings),
                        views.extracted_at.isoformat(),
                        now_str,
                        now_str,
                    ),
                )

    def get_finding_views(self, finding_id: str) -> Optional["FindingViews"]:
        """Retrieve FindingViews object from finding_views table."""
        from src.app.schemas.views import FindingViews, SingleView, ViewQuality, ViewStatus
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM finding_views WHERE finding_id = ?",
                (finding_id,),
            ).fetchall()

        if not rows:
            return None

        views_dict = {}
        missing_views = []
        extracted_at = None

        for row in rows:
            view_type = row["view_type"]
            extracted_at = datetime.fromisoformat(row["extracted_at"])
            single_view = SingleView(
                text=row["view_text"],
                structured=json.loads(row["view_structured"]),
                source_fields=json.loads(row["source_fields"]),
                extraction_method=row["extraction_method"],
                confidence=row["confidence"],
                status=ViewStatus(row["view_status"]),
                warnings=json.loads(row["warnings"]),
            )
            views_dict[view_type] = single_view
            if single_view.status == ViewStatus.MISSING:
                missing_views.append(view_type)

        if not views_dict:
            return None

        quality = ViewQuality(
            available_views=4 - len(missing_views),
            missing_views=missing_views,
            warnings=[],
        )

        embedding_text = {}
        for vt in ["description", "location", "reproduction", "impact"]:
            if vt in views_dict and views_dict[vt].text:
                embedding_text[vt] = views_dict[vt].text

        return FindingViews(
            finding_id=finding_id,
            description=views_dict.get("description", SingleView(status=ViewStatus.MISSING)),
            location=views_dict.get("location", SingleView(status=ViewStatus.MISSING)),
            reproduction=views_dict.get("reproduction", SingleView(status=ViewStatus.MISSING)),
            impact=views_dict.get("impact", SingleView(status=ViewStatus.MISSING)),
            embedding_text=embedding_text,
            view_quality=quality,
            extracted_at=extracted_at or datetime.now(timezone.utc),
        )

    def save_finding_embeddings(self, embeddings: "FindingEmbeddings") -> None:
        """Save FindingEmbeddings object to finding_embeddings table."""
        import uuid
        import hashlib
        from src.app.schemas.views import FindingEmbeddings
        now_str = datetime.now(timezone.utc).isoformat()

        with get_db() as db:
            # Per-view embeddings
            for view_type, vector in embeddings.embeddings.items():
                if vector is None:
                    continue
                input_hash = hashlib.sha256(json.dumps(vector).encode("utf-8")).hexdigest()
                db.execute(
                    """
                    INSERT INTO finding_embeddings (
                        id, finding_id, view_type, embedding_vector, model_name,
                        model_version, embedding_dimension, input_text_hash,
                        generated_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id, view_type) DO UPDATE SET
                        embedding_vector=excluded.embedding_vector,
                        model_name=excluded.model_name,
                        model_version=excluded.model_version,
                        embedding_dimension=excluded.embedding_dimension,
                        input_text_hash=excluded.input_text_hash,
                        generated_at=excluded.generated_at,
                        updated_at=excluded.updated_at
                    """,
                    (
                        f"emb-{uuid.uuid4()}",
                        embeddings.finding_id,
                        view_type,
                        json.dumps(vector),
                        embeddings.embedding_model,
                        embeddings.model_version,
                        embeddings.embedding_dimension,
                        input_hash,
                        embeddings.generated_at.isoformat(),
                        now_str,
                        now_str,
                    ),
                )

            # Combined embedding
            if embeddings.combined_embedding:
                input_hash = hashlib.sha256(json.dumps(embeddings.combined_embedding).encode("utf-8")).hexdigest()
                db.execute(
                    """
                    INSERT INTO finding_embeddings (
                        id, finding_id, view_type, embedding_vector, model_name,
                        model_version, embedding_dimension, input_text_hash,
                        generated_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id, view_type) DO UPDATE SET
                        embedding_vector=excluded.embedding_vector,
                        model_name=excluded.model_name,
                        model_version=excluded.model_version,
                        embedding_dimension=excluded.embedding_dimension,
                        input_text_hash=excluded.input_text_hash,
                        generated_at=excluded.generated_at,
                        updated_at=excluded.updated_at
                    """,
                    (
                        f"emb-{uuid.uuid4()}",
                        embeddings.finding_id,
                        "combined",
                        json.dumps(embeddings.combined_embedding),
                        embeddings.embedding_model,
                        embeddings.model_version,
                        embeddings.embedding_dimension,
                        input_hash,
                        embeddings.generated_at.isoformat(),
                        now_str,
                        now_str,
                    ),
                )

    def get_finding_embeddings(self, finding_id: str) -> Optional["FindingEmbeddings"]:
        """Retrieve FindingEmbeddings object from finding_embeddings table."""
        from src.app.schemas.views import FindingEmbeddings
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM finding_embeddings WHERE finding_id = ?",
                (finding_id,),
            ).fetchall()

        if not rows:
            return None

        embeddings_map = {}
        combined_vec = None
        model_name = "all-MiniLM-L6-v2"
        model_version = None
        dim = 384
        generated_at = None

        for row in rows:
            vt = row["view_type"]
            generated_at = datetime.fromisoformat(row["generated_at"])
            model_name = row["model_name"]
            model_version = row["model_version"]
            dim = row["embedding_dimension"]
            vec = json.loads(row["embedding_vector"]) if row["embedding_vector"] else None

            if vt == "combined":
                combined_vec = vec
            else:
                embeddings_map[vt] = vec

        missing_views = [vt for vt in ["description", "location", "reproduction", "impact"] if vt not in embeddings_map or embeddings_map[vt] is None]

        return FindingEmbeddings(
            finding_id=finding_id,
            embedding_model=model_name,
            model_version=model_version,
            embedding_dimension=dim,
            embeddings=embeddings_map,
            combined_embedding=combined_vec,
            generated_at=generated_at or datetime.now(timezone.utc),
            missing_views=missing_views,
        )


repo = FindingsRepository()

