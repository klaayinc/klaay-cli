# collected_evidences

## What it is

A single piece of evidence — either **manual** (a file or URL a human
attached) or automated (extracted via an integration). `attributes.manual`
is derived automatically server-side from `files.attached? || url.present?`
— you cannot set it directly, just attach a file or set a URL.

## Role in the SOC 2 journey

This is the raw material `evidence_checks` evaluates. On its own, creating a
`collected_evidences` record does nothing for compliance status — it has to
be linked to a control (see below) and then checked.

Attaching a file drives the real ActiveStorage direct-upload flow, not a
plain multipart POST — the `klaay` CLI's `--file <relationship>=<path>` flag
on `create`/`update` handles this for you. `files` and `url` are mutually
exclusive; a record has one or the other, never both.

## Commonly used with

- **`collected_evidence_selected_control_users`** — the only way to connect
  evidence to a control; `collected_evidences` has no direct relationship to
  `selected_controls`. This is a separate `create` call after the evidence
  itself exists.
- **`evidence_checks`** — what actually consumes the evidence to decide if a
  control is satisfied.
- `meta.possible_file_formats` on the response lists the accepted content
  types for this account (attachment limits are per-attachment, not
  universal — a different resource's attachment may allow a different set).
