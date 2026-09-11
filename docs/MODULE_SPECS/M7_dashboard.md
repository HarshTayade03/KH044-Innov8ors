# M7 dashboard API contract

The analyst dashboard reads persisted pipeline rows only. It never derives or
fabricates measured totals. Empty collections are valid responses (`data_status:
"empty"`); repository failures are returned as normal API errors. Responses
include `simulation_labels` where applicable so mock feeds and lab simulation
cannot be mistaken for production evidence.

## Endpoints

* `GET /api/v1/dashboard/metrics` returns stored finding, active issue,
  cluster, priority, case, and validation counts plus case-status counts.
* `GET /api/v1/dashboard/cases` (alias `/dashboard/case-queue`) returns a
  paginated queue of stored cases, joined to active issue and priority rows.
* `GET /api/v1/dashboard/cases/{case_id}` returns case data, source findings
  and four-view data, priority, latest validation/evidence, cluster, and audit
  timeline. Missing cases are 404.
* `GET /api/v1/dashboard/cases/{case_id}/validation` and `/evidence` expose
  persisted validation records and immutable redacted artifacts; no record is
  represented by an empty list.
* `GET /api/v1/dashboard/clusters/{cluster_id}` returns the cluster and member
  finding summaries for side-by-side inspection. Missing clusters are 404.
* `GET /api/v1/dashboard/cases/{case_id}/audit` returns append-only audit rows.

Case generation and review mutations remain owned by the M6 case module.
