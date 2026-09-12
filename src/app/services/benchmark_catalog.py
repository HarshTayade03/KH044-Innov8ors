"""Static catalog for permitted benchmark metadata; never clones or executes targets."""

from src.app.schemas.benchmarks import BenchmarkCatalog, BenchmarkKind, BenchmarkSource


class BenchmarkCatalogService:
    def get_catalog(self) -> BenchmarkCatalog:
        return BenchmarkCatalog(
            safety_policy=(
                "Benchmark repositories are metadata/data inputs only. Vulnerable applications "
                "and repositories must run in an isolated, authorized environment outside the API; "
                "real sandbox execution remains disabled by default."
            ),
            sources=[
                BenchmarkSource(
                    source_id="owasp-benchmark-java",
                    name="OWASP Benchmark Java",
                    kind=BenchmarkKind.APPLICATION,
                    url="https://github.com/OWASP-Benchmark/BenchmarkJava",
                    purpose="Measure SAST/DAST/IAST detection and scoring against labeled Java cases.",
                    expected_artifact="Scanner exports plus benchmark scorecard metadata.",
                    provenance_note="Use a local isolated lab only; do not expose the application publicly.",
                    license_note="Review the repository license and benchmark terms before redistribution.",
                ),
                BenchmarkSource(
                    source_id="llm-sast-triage",
                    name="LLM-Assisted SAST Triage",
                    kind=BenchmarkKind.TRIAGE_PIPELINE,
                    url="https://github.com/vishnushri19/llm-sast-triage",
                    purpose="Compare scanner-first clustering, evidence preservation, and LLM explanation.",
                    expected_artifact="Semgrep JSON findings, labels, and evaluation metrics.",
                    provenance_note="Treat the LLM as explanation only; scanner evidence remains authoritative.",
                ),
                BenchmarkSource(
                    source_id="tencent-vulngym",
                    name="Tencent VulnGym",
                    kind=BenchmarkKind.LOCALIZATION,
                    url="https://github.com/Tencent/VulnGym",
                    purpose="Evaluate repository-scale localization with entry points, operations, and traces.",
                    expected_artifact="JSONL reports/entries containing repository, commit, and trace provenance.",
                    provenance_note="Checkout and analyze only authorized commits in an isolated read-only lab.",
                ),
                BenchmarkSource(
                    source_id="0sec-triage-dataset",
                    name="0sec Triage Dataset",
                    kind=BenchmarkKind.DATASET,
                    url="https://docs.0.security/research/triage-dataset/",
                    purpose="Evaluate alert/vulnerability triage features and ranking behavior.",
                    expected_artifact="Dataset records and labels with source documentation.",
                    provenance_note="Preserve dataset license, feature provenance, and label limitations.",
                ),
                BenchmarkSource(
                    source_id="secalertbench",
                    name="SecAlertBench",
                    kind=BenchmarkKind.DATASET,
                    url="https://github.com/Dxsssu/SecAlertBench",
                    purpose="Measure attack/non-attack alert triage, false-positive control, and consistency.",
                    expected_artifact="Normalized alert JSON and evaluation labels.",
                    provenance_note="Use released/redacted data only; do not infer identities from alert fields.",
                ),
                BenchmarkSource(
                    source_id="vulnerability-localization-benchmark",
                    name="Vulnerability Localization Benchmark",
                    kind=BenchmarkKind.LOCALIZATION,
                    url="https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark",
                    purpose="Evaluate file-level vulnerability localization and patched-code true negatives.",
                    expected_artifact="MD5-verified repository pairs and Phase A/B results.",
                    provenance_note="Docker evaluation is a separate controlled lab capability, not enabled here.",
                ),
            ],
        )


benchmark_catalog_service = BenchmarkCatalogService()
