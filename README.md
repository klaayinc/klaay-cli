# klaay

Command-line client for the Klaay API. A single, self-contained binary — no
Node, Ruby, or Python runtime required.

## Quickstart for AI agents

If you're an agent (Claude Code or otherwise) driving this CLI on a
developer's behalf, this is the loop:

1. `klaay login` once, interactively, on the developer's own machine. The
   token is cached (in the OS keychain when available) for ~3 months —
   every command after that just works with no re-authentication.
2. `klaay resources` to see what's available — every resource type Klaay
   exposes, derived live from the account's own `GET /openapi` spec, not a
   hardcoded list.
3. `klaay describe <resource>` before your first `list`/`create`/`update`
   against any resource you haven't used yet. For the ~20 resources central
   to the SOC 2 journey (`selected_controls`, `evidence_checks`,
   `collected_evidences`, `policies`, `vendors`, `selected_risk_scenarios`,
   `workstreams`, `compliance_stats`, etc.), this also prints hand-written
   guidance on what the resource *is*, where it fits in the compliance
   program, and which other resources it's normally used alongside — not
   just mechanical params. Everything after that is live filters/sortable
   fields/attributes pulled from the account's own spec — don't guess field
   names.
4. From there, the generic commands (`list`, `get`, `create`, `update`,
   `delete`, `status`, `call`) cover the rest.

Every error is the API's own JSON:API error body printed as-is (`errors[].title`/
`.detail`) — nothing invented by the CLI. If a command fails, read that body;
it tells you exactly what went wrong.

## Install

No published release or crates.io listing exists yet — distribution channel
(GitHub Releases install script, Homebrew tap, `cargo install` via crates.io)
is still an open decision (see the plan). Until then, build from source:

```
cargo build --release
# binary at target/release/klaay
```

## Developing against a local Kiln

`bin/dev-cli <args>` runs the CLI with an always-fresh build and
`KLAAY_API_URL` defaulted to `http://localhost:3000` (Kiln's `bin/dev`
default port) unless already set. It's one-shot: `cargo run` rebuilds only
when sources changed, runs your command, and returns to the prompt — it does
not hold the terminal:

```
bin/dev-cli login --email dev@example.com
bin/dev-cli list selected_controls --page-size 5
```

Pass `--watch` as the first argument to opt into a save-rerun loop instead —
it re-executes the command on every source change and holds the terminal
until Ctrl-C. That mode needs [`watchexec`](https://watchexec.github.io/) on
`PATH` (`cargo install watchexec-cli` or `brew install watchexec`) — not
`cargo-watch`, which hasn't been updated since October 2024:

```
bin/dev-cli --watch list selected_controls --page-size 5
```

## Auth

```
klaay login --email you@company.com
```

Prompts for your password (or pass `--password`). If you belong to more than
one Klaay account, you'll be shown the list and prompted to pick one — or
pass `--account <id>` upfront if you already know it. SSO is also supported:

```
klaay login --google        # opens your browser
klaay login --microsoft     # prints a device code to enter at microsoft.com/devicelogin
```

SSO needs `GOOGLE_AUTH_CLI_CLIENT_ID` / `MICROSOFT_AUTH_CLI_CLIENT_ID` (and
optionally `MICROSOFT_AUTH_CLI_TENANT`) set to a CLI-specific OAuth client —
Klaay's existing web-app OAuth clients can't do a CLI-style redirect or
device-code flow. These must match the same-named env vars on the server
exactly, since both sides need to agree on the same registered client id.
Until those are registered (see the plan), `--google`/`--microsoft` fail with
a clear message rather than a confusing network error.

`klaay whoami` shows who you're logged in as; `klaay logout` clears the
stored session.

Point at a non-default environment (e.g. local dev) with `--api-url` or the
`KLAAY_API_URL` env var — the default is `https://api.klaay.com`.

## Commands

| Command | What it does |
|---|---|
| `klaay login` | Authenticate and store a token (password or `--google`/`--microsoft`) |
| `klaay logout` | Clear the stored token |
| `klaay whoami` | Show the current session (calls `GET /me`) |
| `klaay resources` | List every resource type, derived from `GET /openapi` |
| `klaay describe <resource>` | Show what a resource is, its role in the SOC 2 journey, and commonly-paired resources (for the ~20 core resources — see below), plus live filters/sortable fields/attributes for any resource |
| `klaay list <resource>` | List a collection — `--filter k=v` (repeat for multi-value), `--sort`, `--include`, `--fields`, `--page-number`, `--page-size` |
| `klaay get <resource> <id>` | Fetch one resource — `--include`, `--fields` |
| `klaay create <resource>` | Create — `--data '<json fragment>'`, `--file relationship=path` (repeatable) |
| `klaay update <resource> <id>` | Update — same flags as `create` |
| `klaay delete <resource> <id>` | Delete |
| `klaay call <method> <path>` | Low-level escape hatch for non-CRUD endpoints (`GET /me`, `.../stats`, etc.) |
| `klaay status` | Readiness snapshot — same numbers as the "Road to Readiness" widget (admin-only) |

Run `klaay <command> --help` for a worked example of any command.

## Filters — array vs scalar

A single `--filter key=value` sends `filter[key]=value`. Repeating the same
key sends `filter[key][]=value` for each occurrence:

```
klaay list selected_controls \
  --filter state_include=ready --filter state_include=implemented
```

This matters: Klaay's `_include`-style filters expect a real array and
silently match nothing against a comma-joined string. `klaay describe
<resource>` tells you which filters are array-typed.

## Resource guidance (`skills/`)

`skills/*.md` holds hand-written, carefully-considered guidance for the ~20
resources central to the SOC 2 compliance journey — what each one is, how it
fits into the program (grounded in Klaay's own compliance-workflow
documentation and real model relationships, not invented), and which other
resources it's normally used alongside. These are embedded into the binary
at compile time (`src/skills.rs`) and shown by `klaay describe <resource>`
above the live spec-derived section. This is content Kiln's OpenAPI spec
can't capture on its own — it's narrative workflow knowledge, not a filter
or attribute list — so it's curated here instead of auto-derived.

Resources outside this set still get full `describe` output — just the
live filters/sortable fields/attributes section, no curated intro. Extend
coverage by adding `skills/<resource>.md` and a match arm in
`src/skills.rs`.

## File uploads

`--file <relationship>=<path>` on `create`/`update` drives the real
ActiveStorage direct-upload flow (checksum, blob registration, upload, then
attaching the resulting blob to the relationship) — not a plain multipart
POST. Attaching a file to `collected_evidences` is exactly how you record
manual evidence:

```
klaay create collected_evidences --file files=./screenshot.png
```

Linking that evidence to a control is a separate step (there's no direct
relationship from evidence to a control — only through a join resource):

```
klaay create collected_evidence_selected_control_users \
  --data '{"relationships":{"collected_evidence":{"data":{"type":"collected_evidences","id":"<id>"}},"selected_control":{"data":{"type":"selected_controls","id":"<id>"}}}}'
```

## Where things are stored

```
~/.config/klaay/
  credentials.json     # only exists if the OS keychain wasn't available (0600 perms)
  openapi-cache.json    # cached spec used by `resources`/`describe` (--refresh to force a re-fetch)
```

There's no persisted config file for non-secret prefs yet — `--api-url`/`KLAAY_API_URL` needs to be passed on every invocation if you're not using the default.

When the OS keychain is available (the common case on macOS/Windows/Linux
desktops), the token lives there instead, under the service name `klaay-cli`.
Uninstalling the binary doesn't touch either — `klaay logout` is the explicit
way to clear a session.
