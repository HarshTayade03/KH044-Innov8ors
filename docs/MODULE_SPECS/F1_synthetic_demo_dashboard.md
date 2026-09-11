# F1 synthetic corpus demonstration dashboard

## Goal

Demonstrate the implemented pipeline from repository-owned scanner fixtures. The UI does not ask
an analyst to upload, paste or manually enter findings. It presents the six prepared exports as a
fixed catalog, loads them through a safe backend route, and exposes the resulting evidence.

## Experience and contracts

- `GET /api/v1/demo/datasets` returns six fixed metadata records totaling 110 findings.
- `POST /api/v1/demo/datasets/{id}/load` reads only the mapped file under `data/`; arbitrary paths
  and unknown IDs return 404.
- `GET /api/v1/dashboard/metrics` reports stored findings, active issues, clusters, priorities,
  validations and artifacts.
- The browser can load one export or all six, run views, embeddings, deduplication and risk, then
  inspect findings, canonical issues, cluster reasons and risk contributions.
- An issue action runs the M5 offline simulator, retrieves redacted/hash-addressed evidence and
  recalculates risk. The UI labels simulation as supporting evidence rather than exploit proof.
- Use local HTML/CSS/JS with no build step or external asset dependency. Responsive layouts must
  retain every control and avoid horizontal page overflow.

## Acceptance

Catalog count and fixed-path loading are tested; existing regression tests pass; JavaScript syntax
passes; rendered interaction is checked when the configured browser surface is available.
