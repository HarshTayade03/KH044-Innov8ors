# Repository agent instructions

Applies to the entire repository. Read these before working:

1. [Development guide](docs/agent-instructions.md)
2. [Current modules and features](docs/CURRENT_STATE.md)
3. [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
4. [Task log](TASK_LOG.md)

Use the public name **AI-Assisted Vulnerability Triage Platform**; AI-Assisted Triage is internal only.
Inspect code before making claims. Distinguish implemented, verified, partial, and planned work.
Work on feature branches and preserve unrelated changes. Keep schemas as contracts, business
logic in services, and persistence in repositories. Preserve original evidence; sanitize derived
artifacts before display. Simulated outcomes never prove real exploitability. Human analysts
retain final approval authority. Real sandbox execution stays disabled by default.

Read an existing module spec before implementation. If absent, document contracts and acceptance
criteria first. Run relevant checks and record blocked checks honestly. Update TASK_LOG.md for
completed work and keep status/plan documents aligned. Do not edit secrets or .env without explicit
authorization. Product references describe intended behavior, not completed features.
