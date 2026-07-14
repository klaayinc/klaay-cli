# policies

## What it is

A governance policy document (e.g. "Access Control Policy"), usually
instantiated from a `policy_template`. Related to `frameworks`/
`framework_criteria` directly (via `policy_frameworks`/`policy_criteria`) —
publishing the right policies is itself part of framework coverage, not just
a prerequisite for employee acknowledgement.

## Role in the SOC 2 journey

Fulfilled when at least one **published** `policy_version` exists.

**Start this area early — earlier than its complexity would suggest.** Content
drafting is fast (a `workstream` with `topic: "policy"` gets the AI to draft
from the template in minutes), but the policy isn't `publishable`
(`meta.publishable`) until every `{[REPLACE:...]}` (needs a specific company
fact) and `{[CLARIFY:...]}` (needs a decision) placeholder is resolved, and
content isn't empty. Once published, **employee acknowledgement is the
single longest lead time in the entire compliance program** — it can take
days to weeks for every employee to individually acknowledge. Kicking off
policies first lets that clock run in the background while you focus on
controls.

## Commonly used with

- **`policy_versions`** — the actual publish step; check
  `meta.publishable` on the policy before creating one.
- **`workstreams`** (`topic: "policy"`) — AI drafting and placeholder
  resolution.
- **`framework_criteria`** / **`frameworks`** — what this policy counts
  toward directly.
- Employee acknowledgement itself isn't a directly-called resource here —
  it's tracked via the `employees` area of `compliance_stats`, triggered
  automatically the moment a `policy_versions` is published.
