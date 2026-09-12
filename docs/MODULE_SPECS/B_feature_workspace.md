# B: shared feature workspace

Reuse the existing selected design and synthetic loader. Add an accessible feature navigation,
per-view search and filter state, dedicated priority/validation/system views, and richer source,
view and risk details. Close must remain usable while requests run. Capture modal opener and return
focus on close. Progress and errors must be announced. Pagination must retrieve all records, not
silently stop at 500. Failed refreshes retain the previously displayed collection and identify stale
data. Module requests should report structured API errors as readable text.

Validation view initially lists latest runs referenced by priorities, explicitly not full run
history. Show all artifacts and compare SHA-256 against served content before claiming verification.
Cases navigation opens the concurrent review queue; paginated refresh includes cases. Bulk generation must have a defined handler at dashboard initialization.

Acceptance: JS syntax, frontend behavior checks for pagination/errors/filter state and existing
backend regression where available. Browser verification must be reported separately if unavailable.
