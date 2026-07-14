# policy_versions

## What it is

An immutable, published snapshot of a policy's content —
`meta.version` (integer) and `meta.html` (rendered content).

## Role in the SOC 2 journey

Creating one is the action that actually **triggers employee acknowledgement
assignments** — nothing else does. It requires the parent policy to already
have real, resolved content (see `policies` — `meta.publishable` must be
true first, or the create will fail).

Because acknowledgement is the longest lead time in the whole program,
publishing early (even a first draft version) starts that clock sooner.

## Commonly used with

- **`policies`** — the parent; you always create a version against an
  existing policy via the `policy` relationship.
- Employee acknowledgement progress shows up in `compliance_stats`'
  `employees`/`policies` areas, not as a directly queryable relationship on
  this resource.
