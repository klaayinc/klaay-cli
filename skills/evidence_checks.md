# evidence_checks

## What it is

An AI-run evaluation of whether the evidence currently attached to a control
actually satisfies it.

## Role in the SOC 2 journey

This is the mechanism that flips a control to `fulfilled` in
`compliance_stats` — nothing else does. `state: "implemented"` on a control
is not enough by itself.

`POST /evidence_checks` (with the `selected_control` relationship) returns
`202 Accepted` — it runs asynchronously. Poll with
`GET /evidence_checks?filter[selected_control_id_eq]=<id>` until a result
appears. The result's `meta` carries `passed`, `justification`,
`confidence_score`, `checked_at`, and `since`.

If a check **fails** on a control that was `implemented`, the control is
automatically demoted to `misconfigured` — recovery is: fix the underlying
issue, wait for `meta.implementation_checks_passing` to go true again,
manually advance the state back through `ready` → `implemented`, then re-run
the check.

## Commonly used with

- **`selected_controls`** — what's being checked; the `selected_control`
  relationship is required on create.
- **`collected_evidences`** / **`collected_evidence_selected_control_users`**
  — evidence must already be attached before a check has anything to
  evaluate; if a check fails, read `meta.justification`, attach better
  evidence, and re-run.
