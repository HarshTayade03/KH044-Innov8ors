# M6: case assembly and human review

## Boundary

M6 assembles one reviewable case from an active canonical issue and its persisted
pipeline outputs. Case content is a snapshot of reported findings, derived views,
embedding provenance, priority, validation and redacted evidence references. A
case never changes scanner evidence and never auto-approves.

## Contracts

- Generating a case for a missing or retired issue returns 404.
- A non-stale pending case is reused. A stale case is rebuilt in place and marked
  current before it can be reviewed; the rebuild is recorded in the audit log.
- Approve, reject, evidence-request and priority-override actions require a
  nonblank actor and reason. They update the case and review record in one SQLite
  transaction and append an audit event in the same transaction.
- Repeated terminal decisions and decisions against stale cases return 409.
- Case content labels reported, derived, simulated and mock data through its
  embedded source metadata; it is not evidence of exploitability.

## HTTP contract

- `POST /api/v1/canonical-issues/{issue_id}/generate-case` returns `201` with a
  case snapshot. Missing or inactive issues return `404`; an existing current
  pending case is returned unchanged.
- `GET /api/v1/cases?status=&limit=&offset=` returns `{total, limit, offset,
  cases}`. `GET /api/v1/cases/{case_id}` returns the case plus `reviews` and
  chronological `audit_events`; missing cases return `404`.
- `POST /api/v1/cases/{case_id}/approve`, `/reject`, `/request-evidence` and
  `/override-priority` accept `{actor_id, reason, comment?, new_tier?}`.
  Approve/reject/evidence requests require actor and reason. Overrides also
  require `new_tier` equal to `Immediate`, `Accelerated` or `Standard`.
- Successful review responses return the complete case detail. Invalid payloads
  return `422`; missing cases return `404`; stale cases, repeated terminal
  decisions and compare-and-set races return `409`.

## Acceptance

Assembly is idempotent, missing prerequisites are represented explicitly, review
history preserves actor/reason/status transitions, concurrent terminal decisions
produce one winner, priority overrides update the persisted tier atomically, and
stale cases cannot be approved until regenerated.