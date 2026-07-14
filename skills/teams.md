# teams

## What it is

An org-chart grouping of `account_users` — a way to organize employees for
ownership and reporting rather than a compliance-status-bearing resource
itself.

## Role in the SOC 2 journey

Supporting/organizational — teams don't have their own fulfilled/failing
state in `compliance_stats`. They're useful for assigning ownership of
controls, vendors, or risk scenarios to a group rather than one person, and
for `compliance_stats`-adjacent reporting broken down by org unit.

## Commonly used with

- **`team_memberships`** — the join to add someone to a team; requires the
  **`account_user`** id (not the `user` id) — check
  `relationships.account_user` on the `users` response to find it.
- **`account_users`** — the people being organized.
