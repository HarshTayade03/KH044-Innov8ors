# M6: Cases and human review

## Contract

Cases are materialized snapshots of one active canonical issue. Generation reads the
canonical issue, its normalized source findings and derived views, the current priority,
the latest validation run and its artifact references. Raw scanner evidence remains
unchanged; `case_data` is a JSON snapshot and may be regenerated.

Case status is `pending_review`, `approved`, `rejected`, or `more_evidence_requested`.
Only an analyst action may change status. Every review action requires a nonblank
`actor_id` and `reason`; every action appends an immutable audit event in the same
SQLite transaction. Terminal decisions (`approved` and `rejected`) cannot be repeated
and return HTTP 409. Cases are never auto-approved. Stale cases are not reviewable.

## API

* `POST /canonical-issues/{id}/generate-case`
* `GET /cases?status=&limit=&offset=`
* `GET /cases/{case_id}`
* `POST /cases/{case_id}/approve|reject|request-evidence`
* `POST /cases/{case_id}/override-priority`

Review request bodies contain `actor_id` and `reason`; priority overrides additionally
contain `priority` (a JSON object). Missing records return 404, invalid transitions and
stale cases return 409, and validation errors return 422.

## Acceptance criteria

1. Active canonical issues assemble complete, provenance-preserving case snapshots.
2. A non-stale pending case is reused; stale cases are surfaced and never silently
   reviewed or approved.
3. Review transitions and audit insertion commit or roll back together.
4. Actor, reason, prior/new status and timestamps are retained for every action.
5. Focused tests cover assembly, missing/stale issues, idempotent generation,
   transitions, required fields, repeated terminal decisions, and audit history.
