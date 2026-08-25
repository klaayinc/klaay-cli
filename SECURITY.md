# Security Policy

## Report a vulnerability

Do not open a public issue for a security problem. Public disclosure puts users
at risk before a fix exists.

Send the report by email to **security@klaay.com**. Include:

- A description of the problem.
- The steps to reproduce it.
- The version or commit you tested.
- The platform (macOS, Windows, or Linux) and its version.

You may encrypt the report. Ask for a key at the same address.

## What happens next

- Klaay confirms receipt within three working days.
- Klaay investigates and agrees a fix timeline with you.
- Klaay credits you in the release notes, unless you ask to stay anonymous.

Please give Klaay a reasonable time to release a fix before you disclose the
problem in public.

## Scope

This policy covers the Klaay CLI in this repository. It does not cover the Klaay
backend service. Report a backend problem to the same address, and Klaay routes
it to the right team.

## Handling your own credentials

The CLI stores your API token in the OS keychain when one is available, and
otherwise in `~/.config/klaay/credentials.json` with 0600 permissions. Run
`klaay logout` to clear a session. Never paste a token into an issue or a pull
request.
