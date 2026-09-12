# A: reliable synthetic dataset loading

The fixed six-dataset catalog remains the only demo input. Dispatch SARIF result records to the
SARIF parser while preserving Burp/Nessus scanner identity and original record bytes/fields.
Use a content-addressed batch identity incorporating loader revision, dataset ID and file bytes.
Serialize check-and-load in one SQLite transaction: retries and concurrent loads return the same
records, while failed loads roll back fully. Changed fixture bytes create a new batch; original
imports and evidence are never deleted or rewritten. Earlier malformed imports remain historical
data; the new loader does not count them as a correct import.

Keep existing load response fields and add `already_loaded` and `finding_ids`. On repeat load,
new normalized counts are zero and already_loaded is the fixture record count. UI reports both.
Acceptance: 110 meaningful findings in fresh storage, correct source scanners and SARIF provenance,
stable identities on retry/concurrent loads, rollback on error, and unchanged original records.
