# C: cluster review and validation history

Preserve the selected palette, fonts and synthetic-only inputs. Cluster detail compares member
scanner, title, CWE, host, path and parameter, with links to source details. Explain that merge/split
changes active issues, invalidates affected priorities and marks dependent cases stale. Only an
explicit action button calls the existing guarded merge/split API. Conflicts retain the comparison
and display a readable inline error. Repeated clicks while busy must not submit again.

Consume Copilot-owned GET /api/v1/canonical-issues/{id}/validations with limit/offset.
Show complete history for a selected issue, independent of priority references. The screen is
explicitly per-issue history, not a global archive. Preserve its last successful result on refresh
failure and allow an issue ID to retrieve retired-issue history. Listing never creates runs. Each run opens all retained artifacts with hash/size checks.

Acceptance: history paging/filter/empty/invalid parameter tests, frontend history selection and
cluster action success/conflict behavior, startup regression and syntax checks. Visual acceptance
requires a connected browser and remains separately tracked.
