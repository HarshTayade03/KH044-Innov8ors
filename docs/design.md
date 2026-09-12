# AI-Assisted Vulnerability Triage Platform — Application Design System

Version: 1.0  
Updated: 2026-09-12  
Source reference: [`../design.md`](../design.md)

## Purpose

This document adapts the editorial visual language in the root design reference to the complete
vulnerability triage application. It covers the implemented synthetic-corpus demonstration and
the planned case-review experience. Product screens must communicate evidence, provenance and
uncertainty clearly. Simulated validation must never look like proof of real exploitability, and
only a human analyst can approve or reject a case.

## Product experience

The application tells one continuous story:

1. Select one or more prepared scanner exports from the 110-finding synthetic corpus.
2. Observe normalization and the four derived finding views.
3. Generate provenance-labelled embeddings.
4. Review deterministic and semantic duplicate clusters.
5. Inspect threat-informed risk factors and remediation tiers.
6. Run controlled offline SQLi, XSS or SSRF simulation and inspect redacted evidence.
7. Generate a case, request more evidence, approve or reject it, and review its audit history.

The first six steps are represented by current APIs. Case assembly, review and audit screens remain
planned until P7 is implemented. Unavailable controls must appear disabled with a concise reason.

## Visual direction

The interface should resemble a calm editorial intelligence product rather than a dark security
console. Use generous whitespace, light display type, structured evidence tables, rounded white or
pastel surfaces and a restrained warm-black action color.

### Color tokens

| Token | Value | Application use |
|---|---:|---|
| `ink` | `#0C0A09` | Headlines, primary text, primary buttons |
| `body` | `#4E4E4E` | Supporting text and descriptions |
| `muted` | `#777169` | Metadata, timestamps and inactive states |
| `sage` | `#CCD5AE` | Completed stages, low-risk context and soft panels |
| `light-sage` | `#E9EDC9` | Secondary cards, neutral success surfaces |
| `ivory` | `#FEFAE0` | Main canvas and light card origin |
| `cream` | `#FAEDCD` | Warnings, pending work and reproduction context |
| `tan` | `#D4A373` | Strong borders, selected context and warm emphasis |
| `white` | `#FFFFFF` | Dense evidence and table surfaces |
| `success` | `#16A34A` | Verified system success only |
| `error` | `#DC2626` | Failures, invalid requests and destructive warnings |

Use the five project palette colors as solid soft surfaces or low-contrast gradients. Gradients are
decorative atmosphere and section depth; buttons remain warm black. Ensure body text has at least
WCAG AA contrast against every tinted surface.

### Typography

- **Doto SemiBold:** locally bundled dotted display face. Use only for the wordmark, hero headline,
  major section titles and selected numerical metrics.
- **Claimcheck:** preferred for corpus and dashboard numbers when a licensed file is supplied. Until
  then, Doto is the deterministic fallback.
- **Times New Roman / modern serif fallback:** editorial secondary headings and large risk scores.
- **Inter / Arial / sans-serif:** body copy, controls, navigation, tables and explanations.
- **Consolas / monospace:** identifiers, hashes, model versions, endpoints and preserved evidence.

Display type is expressive but sparse. Never use the dotted face for paragraphs, table rows, API
payloads or audit events. Body type remains 15–16px with 1.45–1.55 line height.

### Shape, spacing and depth

- Main content width: 1200px; page gutters: 24px desktop and 16px mobile.
- Major section interval: 48–96px depending on information density.
- Feature cards: 16px radius; compact evidence panels: 12px; inputs: 8px.
- Buttons, filters, badges and status controls: full pill radius.
- Borders: 1px hairlines. Hover elevation: one subtle `0 4px 16px rgba(0,0,0,.04)` shadow.
- Pastel orbs can decorate hero and empty states. They cannot sit behind dense evidence text.

## Application shell

The 64px top navigation contains the product wordmark, anchors for Corpus, Pipeline and Evidence,
and a pill link to API documentation. Future authenticated builds add the analyst identity and team
switcher on the right without changing the primary flow.

The hero introduces the decision objective rather than the implementation stack. It contains one
primary action that scrolls to the corpus, the local-backend status card, and two large atmospheric
orbs. Backend status states are connecting, online and unavailable.

## Screen and module specifications

### 1. Synthetic corpus

Display six fixture cards: Burp SQLi, Nessus SQLi, Burp XSS, ZAP XSS, Burp SSRF and Nessus SSRF.
Each card shows scanner, file type, vulnerability family and finding count. A card loads one fixed
dataset; the primary action loads all 110 findings. Never expose a filesystem path input.

States:

- Empty: catalog skeleton while metadata loads.
- Ready: all cards enabled with exact counts.
- Loading: actions disabled and current dataset named.
- Complete: normalized/warning/rejected counts reported.
- Error: actionable API message retained until the next operation.

### 2. Overview metrics

Show raw findings, active canonical issues, cluster history, risk scores and validation runs. Metrics
must come from `/api/v1/dashboard/metrics`; never use placeholder values. Each card receives one
palette tint. Large numbers use Claimcheck with Doto fallback. Labels stay in the body face.

Future metrics add pending cases, approved cases and stale cases only after P7 data exists.

### 3. Pipeline

The stage rail visualizes Views, Embeddings, Deduplication and Prioritization in order. Each stage
shows its purpose and one of waiting, working, complete or failed. Progress text should include real
processed counts. A run cannot start with zero findings.

Offline validation remains an explicit issue action because it requires analyst intent and evidence
inspection. A future orchestrator may offer opt-in simulation but cannot auto-approve the result.

### 4. Findings explorer

The default table shows title, scanner, normalized severity, endpoint and completeness. Search filters
the visible dataset locally. Inspect opens a modal with description, location, reproduction and impact
views plus status, embedding backend and dimension. Missing or inferred evidence is labelled.

Do not render raw scanner HTML. Escape all values and use monospace only for technical fragments.

### 5. Canonical issues and risk

Issue rows show title, source report count, scanners, merge method, remediation tier and score. The
detail modal includes stable identity, merge basis, source membership, latest validation status and
all six score contributions. Mock KEV/EPSS provenance remains visible in the explanation.

Tier badges:

- Immediate: muted red text on pale red.
- Accelerated: warm brown text on cream.
- Standard: deep sage text on light sage.

Color supplements the tier label and never carries meaning alone.

### 6. Cluster inspector

Show cluster ID, method, status, member count, similarity and reasons. A future expanded inspector
places finding evidence side by side and supports Merge, Keep separate and Split actions. Destructive
or membership-changing actions require an explicit confirmation and refresh invalidated risk data.

### 7. Offline validation and evidence

The “Simulate validation” action is a dark pill to distinguish deliberate execution. The result modal
shows scenario, verdict, summary, limitations, exact redacted artifact content and SHA-256 hash.
Always display “Offline simulation — does not prove exploitability” adjacent to the verdict.

Verdict language is `simulated_match`, `simulated_no_match` or `inconclusive`. Do not use “exploited,”
“confirmed vulnerability” or visually equivalent success claims.

### 8. Cases and human review — planned

After P7, add a Case Queue tab with tier, state, age, asset, source count and stale indicator. Case
detail assembles findings, views, cluster reasoning, risk, threat intelligence, validation artifacts
and remediation advice.

Review actions:

- Approve: requires analyst identity and reason.
- Reject: requires analyst identity and reason.
- Request evidence: requires a clear request note.
- Override priority: requires previous/new tier and rationale.

Terminal state changes use focused confirmation dialogs. The audit timeline is append-only and shows
actor, action, reason and timestamp. Stale cases cannot be approved until regenerated.

## Component inventory

| Component | Behavior |
|---|---|
| Primary button | Warm-black pill, white label, minimum 40px height |
| Outline button | Transparent pill, tan/neutral border, dark label |
| Status badge | Pastel pill with visible text label |
| Dataset card | Clickable tinted card with scanner metadata and count |
| Metric card | One project-palette tint and dotted numerical value |
| Pipeline stage | Tinted panel with numbered circle and progress text |
| Evidence table | White/ivory dense surface with sticky headers |
| Search input | 44px white field, 8px radius, 2px ink focus ring |
| Detail modal | 16px rounded evidence surface with dark backdrop |
| Notice | Persistent operation result; red only for actual errors |
| Empty state | Short explanation, next action and optional pastel orb |

## Interaction rules

- Disable repeated submissions while an operation is running.
- Preserve the last useful error message until another operation begins.
- Refresh metrics and affected records after load, pipeline, validation or cluster changes.
- Keep keyboard focus visible and return focus to the triggering control when a modal closes.
- Escape all API-originated text before inserting it into the DOM.
- Use animation only for progress and subtle state transitions; respect reduced-motion preferences.
- Tooltips cannot contain essential information.

## Responsive behavior

At 640–1024px, use two-column datasets and pipeline stages, three-column metrics and a condensed hero.
Below 640px, use one-column cards, hide secondary navigation anchors, make controls full width and
allow evidence tables to scroll inside their card. The document itself must not overflow horizontally.
Every touch target must be at least 40px high with enough surrounding space for a 44px effective area.

## Accessibility

- Use semantic landmarks, headings, tables, labels and native dialogs.
- Maintain a logical heading hierarchy and DOM order independent of visual grids.
- Announce pipeline progress and errors with an appropriate live region.
- Provide text for every state, severity and verdict.
- Trap focus inside open dialogs and support Escape to close.
- Meet WCAG AA text contrast and visible focus requirements.
- Do not rely on dotted display characters for critical identifiers or data values.

## Data and trust language

Use these provenance terms consistently:

- **Reported:** supplied by a scanner fixture.
- **Derived:** normalized, extracted or calculated by the platform.
- **Inferred:** rule-based content with stated confidence.
- **Simulated:** produced by the deterministic offline lab.
- **Reviewed:** explicitly decided by a human analyst.

Synthetic fixtures and mock threat feeds must stay visibly labelled. Hashing fallback embeddings are
lexical representations, not learned semantic evidence. Historical clusters can remain visible while
only active canonical issues appear in the primary queue.

## Definition of done for UI work

A frontend change is complete when:

1. It uses real API data and handles empty, loading, success and error states.
2. Desktop, tablet and mobile layouts preserve all required actions.
3. Keyboard navigation, focus and dialog behavior are verified.
4. No user-controlled HTML is rendered unsafely.
5. Simulation and mock provenance remain visible.
6. JavaScript syntax, backend regressions and relevant browser checks pass.
7. The module spec, current-state document and task log remain aligned.
