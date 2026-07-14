# collected_evidence_selected_controls

## What it is

The join record linking one piece of evidence (`collected_evidences`) to one
control (`selected_controls`). Evidence and controls are many-to-many, and
this join is the *only* way to connect them — neither side has a direct
relationship to the other.

This is an STI (single-table-inheritance) resource. When creating a link
yourself, use the **`collected_evidence_selected_control_users`** subtype
(a human-initiated link). The other subtypes —
`collected_evidence_selected_control_ais` and `..._mechanicals` — represent
AI- or system-initiated links and aren't ones you'd normally create directly.

## Role in the SOC 2 journey

Step one of the evidence loop that gets a control to `fulfilled`:

1. **Link** evidence to the control (this resource).
2. **Run a check** — `POST /evidence_checks`.
3. **Poll** — `GET /evidence_checks?filter[selected_control_id_eq]=<id>`.
4. Passed → the control is fulfilled. Failed → read
   `meta.justification`, attach different evidence, repeat.

## Commonly used with

- **`collected_evidences`** — the evidence being linked; create this first
  if it doesn't already exist.
- **`selected_controls`** — the control being satisfied.
- **`evidence_checks`** — the next step after linking; a check only has
  something to evaluate once at least one link exists.
