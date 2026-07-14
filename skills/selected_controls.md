# selected_controls

## What it is

A control the account has actively adopted, mapped to one or more
`framework_criteria` (SOC 2, ISO 27001, etc.) through `selected_control_criteria`.
This is distinct from `control_templates` (the library a control was
instantiated from) — `selected_controls` are the account's own copies.

## Role in the SOC 2 journey

This is **the primary driver of framework progress** and the most complex,
highest-effort area of the whole compliance program. Two things track control
health, and they are not the same:

- **`attributes.state`** — the control's own lifecycle: `pending` → `ready` →
  `implemented`, or `misconfigured`. `pending → ready` requires
  `meta.implementation_checks_passing == true`; `ready → implemented` is a
  manual `PATCH` once the team confirms it's operational; `implemented →
  misconfigured` happens automatically the moment an evidence check fails.
- **`fulfilled` in `compliance_stats`** — depends on evidence, not state. A
  control can sit at `state: "implemented"` and still show as `failing` in
  compliance_stats if no evidence check has ever run, or the latest one
  failed. Fulfilled requires at least one evidence check AND the most recent
  one having passed.

The per-control loop: check `meta.implementation_checks_passing` → advance
state → attach evidence → run a check → poll → fulfilled (or fix and retry).

## Commonly used with

- **`collected_evidence_selected_control_users`** — the join needed to attach
  evidence; there is no direct relationship from a control to evidence.
- **`evidence_checks`** — `POST` (202, async) evaluates whether attached
  evidence satisfies this control; poll with
  `filter[selected_control_id_eq]=<id>`.
- **`collected_evidences`** — the evidence records themselves.
- **`framework_criteria`** / **`frameworks`** — what this control actually
  counts toward; `include=frameworks` shows it.
- **`owners`** (users) — who's responsible for this control.
- **`workstreams`** (`topic: "selected_control"`) — AI-guided help explaining
  what the control requires, suggesting evidence, or troubleshooting a failed
  check.
