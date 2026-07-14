# framework_selections

## What it is

Records which compliance framework(s) — SOC 2, ISO 27001, etc. — this
account has adopted.

## Role in the SOC 2 journey

`GET /framework_selections?include=framework` is the framework-level
progress signal: the included framework's `meta.progress` is a float
(`0.75` = 75% complete), computed from how control fulfillment maps to that
framework's criteria coverage. This is the single number that answers "are
we done yet" for a given framework — check it alongside `compliance_stats`
(which gives area-level detail behind the same underlying data).

## Commonly used with

- **`frameworks`** — the framework catalog (SOC 2, ISO 27001, etc.) this
  selection points at; always `include=framework` to get `meta.progress`.
- **`selected_controls`** + **`framework_criteria`** — what actually drives
  the progress number; framework progress moves only when controls mapped
  to that framework's criteria become fulfilled.
- **`compliance_stats`** — the area-by-area breakdown behind the same
  overall readiness this resource summarizes at the framework level.
