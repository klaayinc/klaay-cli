# accounts

## What it is

The tenant — one organization's entire Klaay workspace. Every other resource
in this list (controls, policies, vendors, users, risk scenarios) is scoped
to one account. A person (`users`) can belong to more than one account, each
via its own `account_users` record.

## Role in the SOC 2 journey

`GET /accounts/:id` exposes `meta.getting_started` — a set of coarse
onboarding flags (`company_profile_complete`, `logo_uploaded`,
`idp_connected`, `team_configured`, `vendors_added`) that summarize setup
progress at a glance, separate from the detailed area-by-area breakdown in
`compliance_stats`. `meta.seeded` indicates whether every adopted
framework's baseline has finished seeding — useful to check before assuming
`selected_controls`/`framework_selections` data is complete right after
signup.

## Commonly used with

- **`framework_selections`** — which frameworks this account is pursuing.
- **`compliance_stats`** — the detailed readiness breakdown for this
  account.
- **`account_information_answers`** — this account's own profile Q&A.
- A logged-in user with multiple accounts sees this list at login time
  (`GET /accounts` resolves to every account the current user belongs to,
  independent of which one is currently active) — this is how the `klaay`
  CLI itself resolves which account to authenticate against when a login
  is ambiguous.
