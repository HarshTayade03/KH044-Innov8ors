# Benchmark and government-feed integration

The platform now exposes `GET /api/v1/benchmarks` as a provenance catalog for the
authorized benchmark sources supplied for the hackathon.

## Safe benchmark use

The catalog is metadata only. The API does not clone, build, execute, or expose
OWASP Benchmark, VulnGym, or vulnerability-localization targets. Any application
execution must happen in a separately isolated and authorized lab. Scanner exports,
JSONL records, labels, commits, traces, and scorecards may then be imported through
the existing ingestion contracts with their source provenance preserved.

The sources serve different evaluation purposes:

- OWASP Benchmark Java: scanner detection and scorecard accuracy.
- LLM-Assisted SAST Triage: evidence-preserving clustering and explanation behavior.
- Tencent VulnGym: repository-scale entry-point and trace localization.
- 0sec Triage Dataset and SecAlertBench: alert triage, ranking, and false-positive control.
- Vulnerability Localization Benchmark: file localization and patched-code true negatives.

## Government enrichment

Configuration now records the official NIST NVD CVE API, CISA KEV feed, and FIRST
EPSS endpoint. The current deterministic prototype still uses local mock feeds by
default. `THREAT_FEED_REFRESH_ENABLED` defaults to `false`; enabling live refresh
must be an explicit deployment decision with rate limits, response hashing, and
source timestamps. Live data must never overwrite original scanner evidence or be
presented as proof of exploitability.

Current supported feed behavior remains:

- local CISA KEV/EPSS fixtures for repeatable tests;
- explicit unsupported-mode errors for the existing live threat flags;
- no automatic internet polling or background refresh.
