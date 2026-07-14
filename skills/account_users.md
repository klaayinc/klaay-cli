# account_users

## What it is

The membership record joining a `user` (a person) to a specific `account` —
roles (`admin`/`member`/`auditor`/etc.), `employment_date`,
`termination_date`, manager, and per-account compliance state. This is
**different from `users`**: a person can belong to several accounts, each
with its own `account_users` record and its own roles/status. Authorization
(`pundit_user`) is based on this resource, not `users` directly.

## Role in the SOC 2 journey

This backs the `employees` area of `compliance_stats`. An employee is
fulfilled when Klaayguard is installed on their device(s) AND all mandatory
policy acknowledgements are complete. This area is mostly **organizational,
not API-driven**: Klaayguard installation is an IT rollout action, and
acknowledgement assignments are created automatically the moment a
`policy_versions` is published — there's no direct API call that "completes"
an employee. The main lever is publishing policies and then monitoring
`compliance_stats` as acknowledgements land.

## Commonly used with

- **`users`** — the underlying person record.
- **`teams`** / `team_memberships` — org structure (linking requires the
  `account_user` id, not the `user` id).
- **`devices`** — Klaayguard/asset status for this person.
- **`tasks`** / **`workstreams`** — can be attached directly as the subject.
