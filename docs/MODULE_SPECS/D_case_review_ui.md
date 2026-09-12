# D: case review UI

Consume the Copilot-owned M6 contract without backend changes. Case details show status, stale
state, source references, priority and simulation labels, reviews and chronological audit events.
Replace browser prompts with labeled actor/reason fields, optional comment and an override tier.
Allow approve/reject/request-evidence/override only for current nonterminal cases. No action is
submitted until the analyst submits the form; reject blank actor/reason locally and at the API.
Keep form contents on API failure and report errors inside the dialog. Guard duplicate submits.
After success refresh shared collections and show the returned updated case. Stale cases offer
regeneration through existing generate-case; missing/retired issues keep an explicit error.

Acceptance: no prompt-based decisions, correct routes/payloads, errors retain entered text,
terminal/stale controls suppressed, audit content escaped and startup remains functional.
