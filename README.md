# Klaay CLI

[![CI](https://github.com/klaayinc/klaay-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/klaayinc/klaay-cli/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Command-line client for the [Klaay](https://klaay.com) API. A single,
self-contained binary — no Node, Ruby, or Python runtime required.

Klaay is a compliance platform. This CLI drives the same API the web app uses,
so you can script your SOC 2 program or let an AI agent work it for you.

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

Download the binary for your platform from the
[latest release](https://github.com/klaayinc/klaay-cli/releases/latest), then put
it on your `PATH`.

The macOS builds are signed and notarized by Klaay ApS, so Gatekeeper accepts
them without a warning. The Windows build is not signed yet.

```bash
# macOS (Apple silicon)
curl -LO https://github.com/klaayinc/klaay-cli/releases/latest/download/klaay_0.1.0_macOS_arm64.zip
unzip klaay_0.1.0_macOS_arm64.zip && chmod +x klaay && sudo mv klaay /usr/local/bin/

# Linux x86_64
curl -LO https://github.com/klaayinc/klaay-cli/releases/latest/download/klaay_0.1.0_Linux_x86_64.tar.gz
tar -xzf klaay_0.1.0_Linux_x86_64.tar.gz && sudo mv klaay /usr/local/bin/
```

There is no crates.io listing and no Homebrew tap yet.

To build from source instead:

```bash
cargo build --release
# binary at target/release/klaay
```

## Developing against a local server

`bin/dev-cli <args>` runs the CLI with an always-fresh build and
`KLAAY_API_URL` defaulted to `http://localhost:3000` (the Klaay API server's
default development port) unless already set. It's one-shot: `cargo run` rebuilds only
when sources changed, runs your command, and returns to the prompt — it does
not hold the terminal:

```
bin/dev-cli login
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
klaay login
```

Opens your browser at the Klaay login page — sign in with whatever method
your deployment supports (password, Google, Microsoft), approve the CLI on
the consent screen (it shows the same verification code the terminal
printed), and the CLI picks up its token automatically. No OAuth client
registration or provider configuration needed. The CLI listens on
`127.0.0.1` and the browser is sent back there with a one-time code, so the
token binds to this machine: a sign-in someone else started cannot land here.

On a machine with no browser — an SSH session, a container — ask for the
type-in flow instead:

```
klaay login --no-browser
```

That prints a short code and an address. Open the address in any browser you
like and type the code. Nothing is sent to you to click, and the long secret
never leaves your terminal.

For CI, where the operator already holds a credential, pipe a minted token
in:

```
klaay login --with-token < token.txt
```

`klaay whoami` shows who you're logged in as; `klaay logout` clears the
stored session.

Point at a non-default environment (e.g. local dev) with `--api-url` /
`KLAAY_API_URL` (default `https://api.klaay.com`) and, for the browser flow,
`--web-url` / `KLAAY_WEB_URL` (default `https://app.klaay.com`).

## Commands

| Command | What it does |
|---|---|
| `klaay login` | Authenticate and store a token (browser sign-in, `--no-browser`, or `--with-token`) |
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
above the live spec-derived section. This is content the OpenAPI spec
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

## Contributing

Klaay welcomes issues and pull requests. Read [CONTRIBUTING.md](CONTRIBUTING.md)
for the build steps, the checks a change must pass, and the writing standard.
The CLA Assistant bot asks you to sign the [CLA](CLA.md) on your first pull
request.

Report a security problem in private. Follow [SECURITY.md](SECURITY.md); never
open a public issue for one.

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for the full text and
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for the crates this binary
links.

The code is free software. The names and the logo are not — see
[TRADEMARK.md](TRADEMARK.md).

Copyright (C) 2026 Klaay ApS.
