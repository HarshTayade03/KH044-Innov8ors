"""
services/embedding.py — SentenceTransformer embedding generation & vector math utilities with pure Python fallback.

Defined according to docs/MODULE_SPECS/M2_views_embeddings.md.
"""

import math
import hashlib
from datetime import datetime, timezone
from typing import Optional, Any

from src.app.config import settings
from src.app.schemas.views import FindingViews, FindingEmbeddings

# Try importing numpy, fallback to pure python if not present
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

# Singleton SentenceTransformer or Fallback Embedder model instance
_model = None


class FallbackEmbedder:
    """
    Lightweight, zero-dependency fallback embedder.
    Uses SHA-256 feature hashing to convert text into deterministic L2-normalized 384-dimensional float vectors.
    Runs on any machine without C-extensions or native DLLs.
    """

    def __init__(self, dimension: int = 384):
        self.dimension = dimension

    def get_sentence_embedding_dimension(self) -> int:
        return self.dimension

    def _hash_word(self, word: str) -> int:
        digest = hashlib.sha256(word.encode("utf-8")).digest()
        return int.from_bytes(digest[:4], "big") % self.dimension

    def encode_single(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        words = text.lower().split()
        if not words:
            return vector

        for word in words:
            idx = self._hash_word(word)
            vector[idx] += 1.0

        # L2 Normalize
        sq_sum = sum(v * v for v in vector)
        if sq_sum > 0:
            norm = math.sqrt(sq_sum)
            vector = [v / norm for v in vector]
        return vector

    def encode(self, sentences: list[str] | str, normalize_embeddings: bool = True) -> list[list[float]]:
        if isinstance(sentences, str):
            sentences = [sentences]
        return [self.encode_single(s) for s in sentences]


def get_embedding_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer(settings.model_name)
            print(f"[embedding] Loaded SentenceTransformer model '{settings.model_name}'")
        except (ImportError, Exception) as e:
            print(f"[embedding] SentenceTransformer not available ({e}). Using FallbackEmbedder (dimension 384).")
            _model = FallbackEmbedder(dimension=384)
    return _model


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Computes cosine similarity between two float vectors (pure Python / numpy optimized)."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0

    if HAS_NUMPY:
        a = np.array(vec_a, dtype=np.float32)
        b = np.array(vec_b, dtype=np.float32)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))
    else:
        dot = sum(x * y for x, y in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(x * x for x in vec_a))
        norm_b = math.sqrt(sum(y * y for y in vec_b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return float(dot / (norm_a * norm_b))


def weighted_similarity(
    embeddings_a: FindingEmbeddings,
    embeddings_b: FindingEmbeddings,
    weights: Optional[dict[str, float]] = None,
) -> float:
    """
    Computes weighted similarity across available views.
    Default weights: description (0.30), location (0.40), reproduction (0.20), impact (0.10).
    Proportionally redistributes weight if a view is missing in either finding.
    """
    if weights is None:
        weights = {
            "description": 0.30,
            "location": 0.40,
            "reproduction": 0.20,
            "impact": 0.10,
        }

    total_weight = 0.0
    weighted_sim_sum = 0.0

    for view_type, default_w in weights.items():
        vec_a = embeddings_a.embeddings.get(view_type)
        vec_b = embeddings_b.embeddings.get(view_type)

        if vec_a is not None and vec_b is not None:
            sim = cosine_similarity(vec_a, vec_b)
            weighted_sim_sum += sim * default_w
            total_weight += default_w

    if total_weight == 0.0:
        return 0.0

    return float(weighted_sim_sum / total_weight)


class EmbeddingService:
    """Service for generating view embeddings and combined embeddings."""

    def __init__(self):
        self.default_weights = {
            "description": 0.30,
            "location": 0.40,
            "reproduction": 0.20,
            "impact": 0.10,
        }

    def _compute_combined_vector(
        self,
        embeddings_map: dict[str, Optional[list[float]]],
    ) -> Optional[list[float]]:
        """Calculates L2-normalized weighted average vector across non-null views."""
        combined_arr = None
        dim = 384
        total_weight = 0.0

        for view_type, weight in self.default_weights.items():
            vec = embeddings_map.get(view_type)
            if vec is not None:
                dim = len(vec)
                if combined_arr is None:
                    combined_arr = [v * weight for v in vec]
                else:
                    combined_arr = [c + v * weight for c, v in zip(combined_arr, vec)]
                total_weight += weight

        if combined_arr is None or total_weight == 0.0:
            return None

        # Divide by total weight and L2-normalize
        avg_vec = [c / total_weight for c in combined_arr]
        sq_sum = sum(v * v for v in avg_vec)
        if sq_sum > 0:
            norm = math.sqrt(sq_sum)
            avg_vec = [v / norm for v in avg_vec]

        return avg_vec

    def generate_embeddings(self, views: FindingViews) -> FindingEmbeddings:
        """Generate vector embeddings for each non-missing view and a combined embedding."""
        model = get_embedding_model()
        dim = model.get_sentence_embedding_dimension() or 384

        texts_to_embed = []
        view_keys = []

        for vt in ["description", "location", "reproduction", "impact"]:
            text = views.embedding_text.get(vt)
            if text:
                texts_to_embed.append(text)
                view_keys.append(vt)

        embeddings_map: dict[str, Optional[list[float]]] = {
            "description": None,
            "location": None,
            "reproduction": None,
            "impact": None,
        }

        if texts_to_embed:
            raw_vectors = model.encode(texts_to_embed, normalize_embeddings=True)
            for key, vec in zip(view_keys, raw_vectors):
                # Convert numpy array or list to python float list
                embeddings_map[key] = [float(x) for x in vec]

        combined_vector = self._compute_combined_vector(embeddings_map)

        missing_views = [
            vt for vt in ["description", "location", "reproduction", "impact"]
            if embeddings_map[vt] is None
        ]

        return FindingEmbeddings(
            finding_id=views.finding_id,
            embedding_model=settings.model_name,
            model_version=None,
            embedding_dimension=dim,
            embeddings=embeddings_map,
            combined_embedding=combined_vector,
            generated_at=datetime.now(timezone.utc),
            missing_views=missing_views,
        )

    def generate_batch_embeddings(self, views_list: list[FindingViews]) -> list[FindingEmbeddings]:
        """Batch embedding generation across multiple findings for high performance."""
        if not views_list:
            return []

        model = get_embedding_model()
        dim = model.get_sentence_embedding_dimension() or 384

        all_texts = []
        text_index_map = []

        for idx, views in enumerate(views_list):
            for vt in ["description", "location", "reproduction", "impact"]:
                text = views.embedding_text.get(vt)
                if text:
                    all_texts.append(text)
                    text_index_map.append((idx, vt))

        if all_texts:
            encoded_vectors = model.encode(all_texts, normalize_embeddings=True)
        else:
            encoded_vectors = []

        finding_embeddings_maps: list[dict[str, Optional[list[float]]]] = [
            {"description": None, "location": None, "reproduction": None, "impact": None}
            for _ in views_list
        ]

        for (idx, vt), vec in zip(text_index_map, encoded_vectors):
            finding_embeddings_maps[idx][vt] = [float(x) for x in vec]

        results = []
        now_dt = datetime.now(timezone.utc)

        for views, emb_map in zip(views_list, finding_embeddings_maps):
            combined_vec = self._compute_combined_vector(emb_map)
            missing = [vt for vt in ["description", "location", "reproduction", "impact"] if emb_map[vt] is None]

            results.append(
                FindingEmbeddings(
                    finding_id=views.finding_id,
                    embedding_model=settings.model_name,
                    model_version=None,
                    embedding_dimension=dim,
                    embeddings=emb_map,
                    combined_embedding=combined_vec,
                    generated_at=now_dt,
                    missing_views=missing,
                )
            )

        return results


embedding_service = EmbeddingService()
