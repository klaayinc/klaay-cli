# Contributing to the Klaay CLI

Thank you for your interest in the Klaay CLI. This guide explains how to build
the binary, how to send a change, and the standards a change must meet.

## License and the CLA

The Klaay CLI is licensed under GPL-3.0-or-later. When you open your first pull
request, the CLA Assistant bot asks you to sign the
[Contributor License Agreement](CLA.md). Sign it once. The bot records your
agreement against your GitHub account and marks later pull requests as covered.

The CLA lets Klaay distribute your change under the project license and keep the
option of a commercial license of the combined work. You keep the copyright to
your contribution.

## Ways to contribute

- Report a bug. Open an issue with the bug report template.
- Request a feature. Open an issue with the feature request template.
- Send a fix or a feature. Open a pull request from your fork.
- Improve the documentation. The same pull request flow applies.
- Add resource guidance. Write `skills/<resource>.md` and a match arm in
  `src/skills.rs`.

For a large change, open an issue first and agree on the approach. This saves you
from a rewrite after review.

## Build from source

You need Rust. The toolchain file pins the version, so `rustup` installs it for
you:

```bash
cargo build --release
# binary at target/release/klaay
```

The crate declares `rust-version = "1.88"`. Do not add a dependency that needs a
newer compiler.

## Run against a local server

`bin/dev-cli <args>` runs the CLI with an always-fresh build. It points
`KLAAY_API_URL` at `http://localhost:3000` and `KLAAY_WEB_URL` at
`http://localhost:5173` unless you set them:

```bash
bin/dev-cli login --email dev@example.com
bin/dev-cli list selected_controls --page-size 5
```

Pass `--watch` as the first argument for a save-rerun loop. That mode needs
[`watchexec`](https://watchexec.github.io/) on `PATH`.

## Before you open a pull request

Run the same checks that CI runs. All must pass:

```bash
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

Add a `// SPDX-License-Identifier: GPL-3.0-or-later` header to every new
first-party Rust source file.

## Pull request standards

- Keep each commit small, logical, and able to be reverted on its own.
- Write a clear commit message. State what the commit does and why.
- Add tests for a fix or a feature. A bug fix needs a test that fails before the
  fix and passes after it.
- Keep the pull request focused. Do not mix unrelated changes.
- Never commit a token, a password, or a real account identifier.

## How a change gets merged

Klaay staff merge to `main`. Branch protection requires a passing CI run and a
review from a maintainer. Open your pull request from a fork; the CI job runs on
it automatically.

## How a release gets published

The release workflow publishes two kinds of GitHub release:

- A nightly. The workflow runs every night. When `main` gained commits since
  the last release, it builds, signs, and publishes a pre-release tagged
  `vX.Y.Z-nightly.YYYYMMDD`. When nothing changed, it skips the night. The
  binary reports the nightly version through `klaay --version`.
- A stable release. A maintainer runs `bin/release X.Y.Z`. The script opens a
  pull request that bumps `Cargo.toml`, waits for it to merge, then dispatches
  the release workflow and watches it to the end.

GitHub marks a pre-release as not "latest", so the install links in the README
always point at the newest stable release.

## Writing standard for prose

All prose in this repository — documentation, code comments, commit messages,
and pull request text — follows ASD-STE100 (Simplified Technical English) and
George Orwell's six rules of writing.

ASD-STE100:

- Use only approved words. One word, one meaning. Technical names and technical
  verbs of this domain are permitted.
- Write in the active voice. Use the present tense where possible.
- Keep sentences short. Use a maximum of 20 words in an instruction and 25 words
  in descriptive text.
- Give one instruction per sentence. Start an instruction with the command form
  of the verb.
- Do not make noun clusters of more than three nouns.
- Do not use slang, idioms, or Latin abbreviations.
- Use a vertical list when you give more than three facts or steps in sequence.
- Start a warning or a caution with the command, not the explanation.

Orwell's six rules:

1. Never use a metaphor, simile, or other figure of speech which you are used to
   seeing in print.
2. Never use a long word where a short one will do.
3. If it is possible to cut a word out, always cut it out.
4. Never use the passive where you can use the active.
5. Never use a foreign phrase, a scientific word, or a jargon word if you can
   think of an everyday English equivalent.
6. Break any of these rules sooner than say anything outright barbarous.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By taking
part, you agree to uphold it. Report unacceptable behavior to security@klaay.com.

## Security

Do not report a security problem in a public issue. Follow the private process in
[SECURITY.md](SECURITY.md).
