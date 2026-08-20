# CLI Rust review rules

These apply to this crate (a `clap` + `ureq` command-line client for the
Klaay JSON:API). Apply them in addition to general Rust guidance. Flag a finding
only when the diff **clearly** violates one of these — when in doubt, stay silent.

## Substance

- Flag added code that could be achieved by deleting, reducing, refactoring, or DRYing up existing code; prefer reusing an existing function, method, or module over new code.
- Flag dead code: unreachable branches (code after a guaranteed `return`/`process::exit`, impossible match arms, never-taken conditions) and disconnected call chains (functions no longer reached from `main`, a subcommand, or a test).
- Flag defensive programming that masks a caller's bug: redundant `Option`/`Result` guards, `unwrap_or`/`unwrap_or_default` fallbacks, or catch-all `Err(_)`/`_ =>` arms that swallow a real error instead of surfacing it. A `?` that propagates, or a top-level `eprintln!` + `process::exit(1)` on genuinely unrecoverable input, is correct — do not flag it.
- Flag error-masking patches that silence a symptom instead of fixing the root cause; prefer a principal fix at the right level over a one-off patch.
- Flag `.unwrap()`/`.expect()`/`panic!`/slice-indexing/integer-cast that can be reached by **untrusted input** (server responses, PR/user args, file contents). Panicking on a genuine internal invariant that the surrounding code guarantees is acceptable when a comment states the invariant.
- Flag secret material (JWTs, passwords, OAuth tokens, id_tokens) that is not wrapped in `zeroize::Zeroizing` at every point it is held, or that is `Debug`-formatted / logged / placed in a struct that derives `Debug`.
- Flag a new abstraction, wrapper, or helper that doesn't match an existing pattern in the crate; require following the established convention (e.g. `BodyKind`, the `ApiResponse`/`ApiClient` accessors, the `bin_name()` helper).

## Comments and hygiene

- Flag comments that restate what the code does; a comment must explain the non-obvious *why* (an invariant, a protocol constraint, a security reason), not narrate mechanics.
- Flag commented-out code and placeholder comments standing in for removed code; delete it.

## Scope discipline (important — this crate has had long review loops)

- Do **not** re-raise a point recorded as RESOLVED in the prior-review background; a resolved thread means it was already handled.
- Do **not** flag pure comment-wording preferences, or re-litigate a phrasing/name that a prior thread already settled, unless the current diff introduces a genuine correctness or safety defect.
- A finding must name a concrete failure (wrong output, panic, leaked secret, dead code, real duplication). Stylistic nitpicks with no behavioural consequence are not findings.
