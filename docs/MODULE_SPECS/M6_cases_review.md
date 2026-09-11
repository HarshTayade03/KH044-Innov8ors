# M6 — Case assembly and human review

Cases are assembled only from an active canonical issue. The snapshot contains the
issue, source normalized findings, available redacted views, stored priority, and
the latest validation/evidence references. A pending case can be regenerated only
when its membership is unchanged; inactive issues and stale snapshots are guarded.

Analysts are the only actors allowed to change status. Every decision requires a
non-blank actor and reason, is performed in one SQLite transaction, writes a review
row and append-only audit event, and transitions only `pending_review` or
`more_evidence_requested` cases. Terminal decisions return a conflict. Evidence
requests return the case to `more_evidence_requested`; no action auto-approves a case.
