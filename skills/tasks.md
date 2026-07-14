# tasks

## What it is

An ad hoc to-do tied to a `subject` (any compliance resource — a vendor, a
control, an account_user, a workstream, etc.) with a due date. General
follow-up tracking that sits outside the structured state machines
(control lifecycle, policy publishing, risk treatment).

## Role in the SOC 2 journey

Not itself part of a fulfilled/failing area in `compliance_stats` — this is
the catch-all for "someone needs to go do a specific thing" (e.g. "review
vendor contract," "follow up on a misconfigured control") that doesn't fit
neatly into one of the tracked areas.

## Commonly used with

- Whatever `subject` it's attached to — the `subject` relationship is
  **required** on create, and can point at vendors, selected_controls,
  account_users, workstreams, or other resources.
- **`title`** is required as well; `PATCH` with `state: "completed"` and a
  `completion_note` to close one out. Valid states: `pending`, `started`,
  `completed`, `failed`.
