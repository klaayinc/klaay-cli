# compliance_stats

## What it is

The account-wide readiness snapshot: one entry per area (`employees`,
`account_information`, `controls`, `risk_scenarios`, `policies`, `vendors`,
`devices`), each carrying a `tally` of states against a `total`. Admin-only.

## Role in the SOC 2 journey

**Always start here.** Before working any specific area, assess the current
posture with this endpoint rather than guessing where to focus — for each
area, `fulfilled / total` gives the completion ratio, and areas with a high
`failing` count relative to `total` need the most attention.

Recommended working order once you've assessed posture: account_information
(quick win) → policies (start early for acknowledgement lead time) →
controls (the main framework driver, most effort) → vendors (parallel to
controls) → risk scenarios (after controls exist) → employees/devices
(mostly organizational, follow from Klaayguard rollout and policy
publishing).

Compliance is not a one-time achievement — controls can regress if a
re-run evidence check fails, new employees need onboarding, new vendors need
assessment. Re-check this endpoint regularly, not just once at the start.

The `klaay status` command is a formatted convenience wrapper around exactly
this endpoint (computing the same overall % the "Road to Readiness" widget
shows); `klaay call GET /compliance_stats` gets you the raw response if you
need to compute something different from it yourself.

## Commonly used with

- **`framework_selections`** — the framework-level view (`meta.progress`)
  of the same underlying completion data.
- Effectively every other resource in this list — this is the dashboard
  over all of them, not a resource with its own workflow.
