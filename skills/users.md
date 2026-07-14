# users

## What it is

The actual person — email, name, and auth identity (`google_sub`/
`microsoft_sub` for SSO-linked accounts). Mostly static reference data.

## Role in the SOC 2 journey

Account-specific state (roles, compliance status, employment dates) does
**not** live here — it lives on `account_users`, the join between a person
and one specific account. A single person can have multiple `account_users`
records (one per account they belong to), each independently admin/member/
terminated/etc. If you're trying to answer "is this employee compliant,"
you want `account_users`, not this resource.

## Commonly used with

- **`account_users`** — the per-account membership and compliance status;
  look here first for anything employee-compliance related.
- **`teams`** (via `team_memberships`, which reference the `account_user`
  id).
