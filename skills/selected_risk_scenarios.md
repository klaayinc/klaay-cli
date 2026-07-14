# selected_risk_scenarios

## What it is

An entry in the risk register — one specific way the organization could be
harmed, usually instantiated from a `risk_scenario_template`.

## Role in the SOC 2 journey

Deliberately sequenced **after** controls: fulfilled requires at least one
related control AND being "treated," so working the control inventory first
is what makes this area tractable.

A scenario stays in `draft` state until **all three** of `treatment`
(`accept`/`mitigate`/`transfer`/`avoid`), `impact` (1–5), and `likelihood`
(1–5) are set — setting only one or two does not exit draft. `transfer` and
`avoid` additionally require a `treatment_note`/`treatment_completion_note`
explaining the strategy; `mitigate`/`accept` don't need extra documentation.

Risk scores and state are computed and live in `meta` (`meta.state`,
`meta.inherent_risk`, `meta.residual_risk`) — not in `attributes`, unlike
most other resources.

## Commonly used with

- **`related_controls`** — must exist before this scenario is meaningful;
  `include=related_controls,owners` when listing.
- **`related_vendors`** / **`related_policies`** — the same "helps mitigate
  this risk" relationship, but to vendors/policies instead of controls.
- **`owners`** (users).
- **`GET /selected_risk_scenarios/stats`** — aggregate weekly inherent/
  residual risk trend across the whole register (a non-CRUD endpoint; reach
  it via `klaay call GET /selected_risk_scenarios/stats`).
