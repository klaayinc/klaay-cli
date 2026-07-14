use crate::client::{ApiClient, HttpMethod};
use crate::config::openapi_cache_path;
use serde_json::Value;
use std::fs;
use std::io::{BufWriter, Write};

/// The invoked binary's own name, for user-facing "run `<this> ...`" hints -
/// avoids hardcoding "klaay" in multiple places, which would go stale if the
/// binary were ever renamed. `pub(crate)` so other modules (e.g.
/// token_store.rs's corrupted-credentials-file message) can reuse it
/// instead of hardcoding their own copy of "klaay". Computed once and
/// cached, since the binary name can't change during a process's lifetime;
/// repeated calls (this file's own call site in `describe`, plus
/// token_store.rs's) would otherwise each re-read `std::env::args()` and
/// re-allocate for a value that's always the same.
pub(crate) fn bin_name() -> &'static str {
    static BIN_NAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        // `args_os()`, not `args()` - `args()` panics during iteration if any
        // argument isn't valid Unicode, which includes argv[0] itself: a
        // non-UTF-8 invocation path would panic on the very first `.next()`
        // call below, never reaching the `.to_str()` fallback this comment
        // used to claim handled that case gracefully. `args_os()` returns
        // `OsString`s that never panic, so a non-UTF-8 argv[0] falls through
        // to `.to_str()` returning `None` (via `Path::file_name()`'s
        // `.to_str()`) exactly as intended.
        //
        // `.to_str()` + `.map(str::to_owned)`, not `.to_string_lossy().
        // into_owned()` - the filename of a Rust binary is always valid
        // UTF-8 in practice, so `to_string_lossy()`'s `Cow<str>` is always
        // the `Borrowed` variant here, and `into_owned()` still forces a
        // heap allocation regardless of which variant it is. `.to_str()`
        // returning `None` (non-UTF-8 path) falls through to the same
        // `unwrap_or_else` fallback as a missing argv[0].
        std::env::args_os()
            .next()
            .and_then(|p| {
                std::path::Path::new(&p)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| env!("CARGO_BIN_NAME").to_string())
    });
    &BIN_NAME
}

/// Fetches GET /openapi (authenticated, no admin requirement) and caches it
/// locally. The spec is Kiln's own generated OpenAPI document - the same one
/// CI's `documentation` job produces and every deployed image ships - so this
/// reflects the live API rather than anything hand-maintained in the CLI.
/// Returns `Err` (rather than exiting internally) on API failure, so the
/// hard-exit contract isn't hidden behind a signature that implies this
/// always succeeds - the caller in `main.rs` handles printing/exiting,
/// consistent with how every other fallible command's `client.*` call
/// already surfaces failure via a return value it inspects.
pub(crate) fn fetch_spec(client: &ApiClient, force_refresh: bool) -> Result<Value, String> {
    // No home directory to cache under - just always live-fetch instead of
    // treating this as fatal; `resources`/`describe` work fine without a
    // cache, just slower.
    let cache_path = openapi_cache_path();
    if !force_refresh {
        if let Some(path) = &cache_path {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(mut cached) = serde_json::from_str::<Value>(&contents) {
                    // The cache is a single shared file regardless of which
                    // `--api-url` is active - without checking `api_url`
                    // here, switching environments (e.g. production to a
                    // local dev server) would silently keep serving the
                    // previous environment's schema (wrong field names,
                    // relationships, filters) with no indication anything
                    // was stale. Older cache files (written before this
                    // check existed) have no `api_url` key at all and are
                    // therefore always treated as stale rather than assumed
                    // to match.
                    let cached_api_url = cached.get("api_url").and_then(|v| v.as_str());
                    if cached_api_url == Some(client.base_url_trimmed()) {
                        // `.take()`, not `.clone()` - `cached` (and its
                        // potentially multi-megabyte "spec" tree) is dropped
                        // right after this block regardless, so cloning it
                        // out would pay for a full deep copy of the parsed
                        // OpenAPI document just to hand back a value that's
                        // about to be the only owner anyway. `take()` swaps
                        // in `Value::Null` and moves the real value out in
                        // its place, at the cost of one `Value::Null`
                        // allocation-free write instead.
                        if let Some(spec) = cached.get_mut("spec") {
                            return Ok(spec.take());
                        }
                    }
                }
            }
        }
    }

    let response = client.call(HttpMethod::Get, "/openapi", None);
    if !response.is_success() {
        return Err(format!(
            "Could not fetch /openapi ({}): {}",
            response.status,
            // `error_detail()`, not a hand-rolled `serde_json::to_string` on
            // the raw body - `to_string` on a `&Value` is infallible (every
            // `Value` variant serializes successfully), so the fallback
            // branch that used to be here was dead code. `error_detail()`
            // also distinguishes a JSON-parse failure from a genuinely empty
            // body, which re-serializing `raw_body()` alone cannot.
            response.error_detail()
        ));
    }
    // The entire cache-write attempt - creating the cache directory, the
    // stale-temp-file scan, and the write-and-rename itself - is Unix-only,
    // gated as one block rather than gating just the write step. Nothing in
    // this cache is ever created or read on non-Unix (see the write step's
    // own `#[cfg(not(unix))]` non-write note below), so unconditionally
    // running `fs::create_dir_all` on every platform - as an earlier
    // revision did - created the config directory on every single
    // `resources`/`describe` invocation on Windows even though nothing was
    // ever placed in it from this code path.
    #[cfg(unix)]
    if let Some(cache_path) = &cache_path {
        if let Some(dir) = cache_path.parent() {
            // 0700 (owner-only), matching `token_store.rs`'s `save_to_file` -
            // this is the same shared `~/.config/klaay` directory
            // (`config::config_dir()`), not a separate one, but a machine
            // with a working OS keyring never calls `save_to_file` at all
            // (the token lives in the keychain, not a file), so `login`
            // alone doesn't guarantee this directory has ever been created.
            // If `resources`/`describe` is the first command to touch it,
            // a plain `create_dir_all` would leave it at the process
            // umask's default (often 0755, world-readable+executable),
            // letting another local user enumerate its contents.
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let create_result = fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir);
            if let Err(e) = create_result {
                eprintln!(
                    "Warning: could not create cache directory {}: {e}",
                    dir.display()
                );
            } else {
                // Unconditional, not just on first creation - `DirBuilder`'s
                // `mode` only applies when it actually creates the
                // directory, so a pre-existing directory (e.g. left over
                // from before this check existed) needs this to actually
                // get tightened.
                if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
                    eprintln!(
                        "Warning: could not tighten permissions on cache directory {}: {e}",
                        dir.display()
                    );
                }
                remove_stale_cache_temp_files(dir);
                // Sibling temp file, renamed atomically over the real
                // path, so a process interrupted mid-write (SIGKILL,
                // power loss) can't leave a truncated cache file for a
                // concurrent reader to see. Mixes the process id with a
                // nanosecond timestamp (not just the pid alone) - pids
                // wrap around and get reused by unrelated processes, so a
                // pid-only name could still collide with a stale temp
                // file from an earlier process that happened to reuse
                // the same pid.
                let unique = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_else(|_| {
                        // Clock is before the epoch (broken/skewed
                        // container clock) - falling back to a fixed
                        // value like 0 would collide with another
                        // process hitting the same fallback, defeating
                        // the whole point of mixing in a timestamp. A
                        // process-local atomic counter is still unique
                        // per call within this process, and combined
                        // with the pid below is enough to avoid
                        // collisions even in this degenerate case.
                        static FALLBACK: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(1);
                        u128::from(FALLBACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    });
                let tmp_path = cache_path
                    .with_file_name(format!("openapi-cache-{}-{unique}.tmp", std::process::id()));
                // Explicit `0o600` - matches `token_store.rs`'s
                // credential files in this same config directory rather
                // than relying solely on the user's umask. The cache
                // holds the `api_url` (potentially an internal endpoint)
                // and the full OpenAPI spec.
                //
                // `create_new` (not `File::create`, which truncates a
                // stale file with the same name silently) - if the
                // unique-name logic above ever produced a genuine
                // collision, this fails loudly with an `AlreadyExists`
                // error instead of quietly overwriting whatever was
                // already at that path.
                use std::os::unix::fs::OpenOptionsExt;
                let write_result = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp_path)
                    .and_then(|file| {
                        let mut writer = BufWriter::new(file);
                        // Explicit `io::Error::other` rather than
                        // `std::io::Error::from` (a `serde_json::Error ->
                        // io::Error` blanket `From` impl that does the
                        // exact same thing under the hood) - semantically
                        // identical either way, but spelling it out here
                        // makes it obvious this is deliberately
                        // collapsing a genuine (if rare, for this value
                        // type) JSON serialization failure into the same
                        // `io::Error` type as a real I/O failure, rather
                        // than an accidental side effect of `?`.
                        //
                        // Explicitly flushes (and propagates any flush
                        // error) rather than relying on BufWriter's
                        // implicit flush-on-drop, which silently
                        // discards a failure - serde_json::to_writer can
                        // return Ok(()) while buffered bytes are still
                        // sitting in the BufWriter, and the rename below
                        // would then promote a truncated temp file to
                        // the real cache path.
                        //
                        // Wrapped with the `api_url` this spec was
                        // actually fetched from - `fetch_spec`'s read
                        // path compares this against the currently
                        // active `api_url` before trusting the cache, so
                        // switching environments can't silently serve a
                        // different environment's schema.
                        //
                        // Serialized field-by-field directly into the
                        // writer, not via `serde_json::json!({"spec":
                        // response.raw_body(), ...})` - embedding a
                        // `&Value` in `json!` produces a full clone of the
                        // entire spec tree (potentially multi-megabyte)
                        // just to immediately serialize it, when
                        // `raw_body()` can be serialized directly without
                        // ever building that intermediate `Value`.
                        use serde::ser::SerializeMap;
                        use serde::Serializer as _;
                        serde_json::Serializer::new(&mut writer)
                            .serialize_map(Some(2))
                            .and_then(|mut map| {
                                map.serialize_entry("api_url", client.base_url_trimmed())?;
                                map.serialize_entry("spec", response.raw_body())?;
                                map.end()
                            })
                            .map_err(std::io::Error::other)
                            .and_then(|()| writer.flush())
                    });
                if let Err(e) = write_result {
                    // `tmp_path`, not `cache_path` - the operation that
                    // actually failed (open/write/flush) was against the
                    // temp file, so showing the final cache path here
                    // would mislead anyone diagnosing e.g. a permissions
                    // error.
                    eprintln!(
                        "Warning: could not write spec cache to {}: {e}",
                        tmp_path.display()
                    );
                    // Best-effort cleanup - but skipped on
                    // `AlreadyExists`. This uses `create_new` (not
                    // `File::create`), so an `AlreadyExists` error means
                    // the temp file genuinely exists already. The
                    // precise invariant established by the scan just
                    // above (`remove_stale_cache_temp_files`, which only
                    // removes files older than an hour) is: any file
                    // with this exact name that still exists at this
                    // point is less than an hour old - so it almost
                    // certainly belongs to another concurrent process
                    // still actively writing it right now, not an
                    // orphaned leftover this same scan would already
                    // have caught. Removing it here would corrupt that
                    // other process's in-flight write. Every other
                    // error kind (permissions, disk full, a write/flush
                    // failure after `open` succeeded) means *this* call
                    // created the file, so cleaning it up is safe.
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        let _ = fs::remove_file(&tmp_path);
                    }
                } else if let Err(e) = fs::rename(&tmp_path, cache_path) {
                    eprintln!(
                        "Warning: could not replace spec cache at {}: {e}",
                        cache_path.display()
                    );
                    let _ = fs::remove_file(&tmp_path);
                }
            }
        }
    }
    // Non-Unix: skip caching entirely, silently - writing with default
    // (potentially world-readable) permissions isn't an option, same
    // reasoning as `token_store.rs`'s `atomic_write_secure`, which
    // explicitly refuses to write its credentials fallback file on non-Unix
    // rather than write it with an uncontrolled ACL. A cache miss here just
    // means the next `resources`/`describe` call live-fetches instead of
    // reading a local copy - much cheaper to accept than for the credentials
    // case, since nothing else depends on this file existing, so there's no
    // warning to print, and (per the `#[cfg(unix)]` above) not even an
    // attempt made.
    Ok(response.into_raw_body())
}

/// Best-effort cleanup of `openapi-cache-*.tmp` files left behind by a
/// process that was killed (SIGKILL, power loss) between creating its temp
/// file and renaming it over the real cache path - nothing else in the CLI
/// ever scans for these, so without this they'd accumulate in the cache
/// directory indefinitely. Only removes files older than an hour, so a temp
/// file actively being written by another concurrent CLI invocation right
/// now is never touched.
///
/// `#[cfg(unix)]` - its sole call site (in `fetch_spec`) is itself inside a
/// `#[cfg(unix)]` block, since these temp files are only ever created there.
#[cfg(unix)]
fn remove_stale_cache_temp_files(dir: &std::path::Path) {
    const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let prefix = "openapi-cache-";
        let suffix = ".tmp";
        if !name.starts_with(prefix) || !name.ends_with(suffix) {
            continue;
        }
        // Requires the portion between `prefix` and `.tmp` to look like this
        // crate's own `{pid}-{unique}` naming (digits and hyphens only,
        // exactly one hyphen) - analogous to `token_store.rs`'s equivalent
        // stale-temp-file scan, but not identical: that one requires exactly
        // two hyphens, for its own `{pid}-{nanos}-{counter}` naming. Each
        // count is correct for its own format; "analogous", not "matches",
        // to avoid implying the two checks are interchangeable.
        // `starts_with`/`ends_with` alone would also match a
        // name like `openapi-cache-editor-backup.tmp`, a plausible file for
        // an editor or another tool to drop in this same cache directory,
        // and silently delete it an hour later even though this CLI never
        // wrote it.
        let middle = &name[prefix.len()..name.len() - suffix.len()];
        if middle.is_empty()
            || !middle.chars().all(|c| c.is_ascii_digit() || c == '-')
            || middle.chars().filter(|&c| c == '-').count() != 1
            || middle.starts_with('-')
            || middle.ends_with('-')
        {
            continue;
        }
        // `.ok()` on the metadata/modified steps (not `io::Error::other` to
        // force `SystemTimeError` through an `io::Result` chain) - a clock
        // going backwards has nothing to do with I/O, and coercing it into
        // `io::Error` just to keep using `.and_then` allocates a box for a
        // value that's immediately discarded anyway.
        //
        // `duration_since` failing means `modified` is *after* `now` (clock
        // skew, an NTP correction, or a file copied from another host with a
        // future timestamp) - checked against the same `STALE_AFTER`
        // threshold in the other direction (`e.duration()` is how far in the
        // future it is), not treated as unconditionally stale. A file dated
        // only a few seconds/minutes ahead - plausible minor clock skew
        // between two machines/processes - could otherwise be deleted while
        // a concurrent process is still actively writing to it, corrupting
        // that write. A file dated hours or days ahead is still caught here
        // immediately rather than waiting for the real clock to catch up to
        // it, which is what "not stale" would otherwise mean.
        // `symlink_metadata` (not `entry.metadata()`/`entry.file_type()`
        // separately) for both the staleness check and the type guard below
        // - `entry.metadata()` follows a symlink to its target's mtime while
        // `entry.file_type()` does not follow it for the type, so a symlink
        // named like a stale temp file (target's mtime old, but the entry
        // itself is a symlink) would previously see `is_stale = true` yet
        // never pass the `is_file()` type guard, leaving it to accumulate
        // indefinitely instead of either being cleaned up or consistently
        // left alone. Using the same (non-following) metadata for both
        // checks means they always agree about which single entry they're
        // describing.
        let symlink_meta = entry.path().symlink_metadata().ok();
        let is_stale = match symlink_meta.as_ref().and_then(|m| m.modified().ok()) {
            Some(modified) => match std::time::SystemTime::now().duration_since(modified) {
                Ok(age) => age > STALE_AFTER,
                Err(e) => e.duration() > STALE_AFTER,
            },
            None => false,
        };
        // Not traversed through a symlink, matching `symlink_meta` above -
        // makes the intent ("this scan only ever touches regular temp files
        // it created") explicit and platform-consistent: `fs::remove_file`
        // on a symlink removes the symlink itself on Unix, but fails with a
        // permission error on Windows for a symlink to a directory - a
        // silent cross-platform behavior difference this guard avoids
        // relying on either way.
        let is_regular_file = symlink_meta.as_ref().map(|m| m.is_file()).unwrap_or(false);
        if is_stale && is_regular_file {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// A resource's own generated tag description, if the operation declares one -
/// this is where Kiln's filters/sortable-fields tables actually live (see
/// public/tags/**/*.md augmentation, kiln-openapi skill), not in per-parameter
/// metadata.
fn tag_description<'a>(spec: &'a Value, tag_name: &str) -> Option<&'a str> {
    spec.get("tags")?
        .as_array()?
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(tag_name))
        .and_then(|t| t.get("description"))
        .and_then(|d| d.as_str())
}

/// Most tag descriptions are just the auto-generated Filters/Sortable Fields
/// tables (see kiln-openapi skill) with no curated prose - only a few
/// (e.g. SelectedControl) have a hand-written intro line from
/// public/tags/*.md. Skip table syntax (`|...`), headings (`#`), horizontal
/// rules/setext underlines (`---`/`===`/`***`), blockquotes (`>`), unordered
/// list items (`- `/`* `/`+ ` - CommonMark's three valid bullet characters),
/// and blank lines to find real prose if there is any.
fn first_prose_line(text: &str) -> &str {
    text.lines()
        .map(|l| l.trim())
        .find(|l| {
            // A horizontal-rule/setext-underline line is any run of 3+ of
            // the same one of these chars (e.g. `---`, `===`, `***`) - not
            // just a line that happens to *start* with 3 of them (the old
            // `starts_with("---")` check would misfire on ordinary prose
            // that merely began with those characters). The 3+ minimum
            // (rather than matching any nonempty run) avoids the opposite
            // false positive: a real prose line reduced to a single `-` or
            // `=` (e.g. a bullet stripped down to its dash) would otherwise
            // be misclassified as a rule and skipped.
            // No `Vec<char>` allocation - each candidate char gets its own
            // fresh `l.chars()` iterator instead of collecting the whole
            // line into a heap buffer just to check its length and
            // uniformity. Short-circuiting happens at two levels: within one
            // candidate, `.all(...)` stops at the first non-matching char;
            // across candidates, the outer `.any(...)` stops entirely once
            // any one of them returns `true` (e.g. for "---", the '-'
            // candidate matches and '=' / '*' are never even tried).
            !l.is_empty()
                && !l.starts_with('|')
                && !l.starts_with('#')
                && !l.starts_with("```")
                // Moved inline (not a separate `let is_rule` computed
                // unconditionally above) so `&&` short-circuiting can skip
                // building the three `l.chars()` iterators entirely once an
                // earlier check (most commonly `!l.is_empty()`, true for
                // every blank line in a real spec) has already rejected `l`.
                && !['-', '=', '*'].iter().any(|&c| {
                    let mut it = l.chars();
                    it.next() == Some(c)
                        && it.next() == Some(c)
                        && it.next() == Some(c)
                        && it.all(|ch| ch == c)
                })
                && !l.starts_with('>')
                && !l.starts_with("- ")
                && !l.starts_with("* ")
                // CommonMark's three valid unordered-list bullet characters
                // are `-`, `*`, and `+` - the first two were handled above,
                // but a bare `+ item` (or a lone `+`, below) fell through
                // both this and the bare-marker check and was misclassified
                // as real prose.
                && !l.starts_with("+ ")
                // A bare bullet marker with no text after it (e.g. a "- " or
                // "* " item stripped down to just its marker, with the
                // trailing space itself trimmed away too) - `is_rule` only
                // catches a run of 3+, and `starts_with("- "/"* "/"+ ")` only
                // catches one *with* a trailing space, so a lone `-`, `*`, or
                // `+` fell through both and was misclassified as real prose.
                && *l != "-"
                && *l != "*"
                && *l != "+"
                // Ordered list markers ("1. ", "10. ", etc.) weren't caught
                // by any of the unordered-bullet checks above, so a numbered
                // list item (common in auto-generated API docs) could reach
                // this function as the "first prose line" - e.g. "1. Records
                // the result of an audit..." instead of real prose. Matches
                // CommonMark's actual ordered-list-marker shape (one or more
                // digits followed by "." or ")" and a space) rather than a
                // bare "starts with a digit" check - the latter would also
                // reject real prose like "2FA is required..." or "3
                // parameters are accepted...", which this shape correctly
                // leaves alone since neither is followed by "."/")" + space.
                && !is_ordered_list_marker(l)
        })
        .unwrap_or("")
}

/// Whether `l` starts with a CommonMark ordered-list marker: one or more
/// digits, then "." or ")", then a space. Deliberately not implemented via
/// `str::split_once` with a `!is_ascii_digit()` predicate - an earlier
/// version tried that, but `split_once`'s "after" half excludes the matched
/// delimiter character itself, so checking that half for a leading "." or
/// ")" can never succeed (confirmed empirically: for "1. Records...",
/// `split_once` yields `("1", " Records...")`, not `("1", ". Records...")`,
/// so `rest.starts_with(". ")` was always false) - the whole check was dead
/// code that never actually rejected anything. `str::find` (which returns
/// the matched position rather than consuming it) keeps the delimiter in
/// the slice this function inspects.
fn is_ordered_list_marker(l: &str) -> bool {
    // `None` and `digit_end == 0` are distinct cases that happen to share
    // the same "no marker" outcome: `None` means every character is a digit
    // (no delimiter at all), while `0` means the very first character
    // already isn't one. Handling them as two explicit early returns (rather
    // than folding `None` into `0` via `unwrap_or(0)`) keeps that distinction
    // visible instead of relying on both cases coincidentally producing the
    // same result today.
    let Some(digit_end) = l.find(|c: char| !c.is_ascii_digit()) else {
        return false;
    };
    if digit_end == 0 {
        return false;
    }
    let after_digits = &l[digit_end..];
    after_digits.starts_with(". ") || after_digits.starts_with(") ")
}

fn operation_tag(operation: &Value) -> Option<&str> {
    operation.get("tags")?.as_array()?.first()?.as_str()
}

/// Returns `Err` instead of printing and returning silently, same rationale
/// as `fetch_spec`/`describe` - without this, `main.rs` had no way to
/// distinguish a genuinely empty spec's success from this "spec has no
/// paths" degraded case, so a script checking `$?` after `klaay resources`
/// would see exit code 0 either way.
pub(crate) fn list_resources(spec: &Value) -> Result<(), String> {
    let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) else {
        return Err("Spec has no paths".to_string());
    };

    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (path, operations) in paths {
        if path.contains('{') {
            continue; // member routes - the collection route carries the description
        }
        // Intentionally omits a collection-level route with neither `get`
        // nor `post` (e.g. a hypothetical write-only/action-only endpoint
        // exposing only `delete`/`patch`/`put`) - `resources` is meant to
        // answer "what can I list/create", and every real resource in this
        // API's spec today exposes at least one of those two. Not the same
        // as the member-route (`path.contains('{')`) skip above, which
        // exists because the *collection* route already carries the
        // description that member route would otherwise duplicate.
        let Some(op) = operations.get("get").or_else(|| operations.get("post")) else {
            continue;
        };
        // Paired lowercase (the spec's own key) / uppercase (for display)
        // literals, rather than a single lowercase array joined and then
        // `.to_uppercase()`'d as a whole - the spec's operation map is
        // already keyed in lowercase, so the uppercase form only exists for
        // display and never needs to touch `operations.get()`. Avoids an
        // extra allocation (`.to_uppercase()` on the already-allocated
        // `.join()` result) for no benefit.
        let methods: Vec<&str> = [
            ("get", "GET"),
            ("post", "POST"),
            ("patch", "PATCH"),
            ("put", "PUT"),
            ("delete", "DELETE"),
        ]
        .into_iter()
        .filter(|(lower, _)| operations.get(*lower).is_some())
        .map(|(_, upper)| upper)
        .collect();
        let tag = operation_tag(op).unwrap_or_default();
        // `map_or`, not `.map(first_prose_line).unwrap_or("")` - the two-step
        // form reads as if the trailing `unwrap_or("")` is guarding against
        // `first_prose_line` itself returning nothing, when it's actually
        // covering the separate case where `tag_description` found no tag at
        // all (`first_prose_line` never returns `Option`; it already falls
        // back to `""` internally for "no prose line found").
        let description = tag_description(spec, tag)
            .map_or("", first_prose_line)
            .to_string();
        rows.push((path.clone(), methods.join("/"), description));
    }
    // Sorted by path alone, not the whole (path, methods, description) tuple -
    // the user's mental model is a sorted list of paths, so ordering driven
    // by description text (whenever two paths happen to share a prefix)
    // would be confusing.
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    // Computed from the actual data (with a sane minimum) rather than fixed
    // widths, which would misalign a row whose path/methods happen to be
    // longer than the hardcoded constant. `.chars().count()` rather than
    // `.len()` - both are ASCII-only in practice (API paths, HTTP method
    // names), so this is a no-op today, but a byte length would silently
    // misalign columns if that ever stopped being true.
    //
    // This is only a floor, not a real ceiling - `/control_template_
    // required_calendar_event_templates` alone (confirmed against
    // config/routes.rb) is already 51 chars, well past this constant, and
    // the `.max()` against the real per-row lengths above already handles
    // that correctly regardless of what this is set to. It exists purely so
    // an API with only short paths doesn't get a needlessly cramped column.
    const MIN_PATH_WIDTH: usize = 45;
    let path_width = rows
        .iter()
        .map(|(p, _, _)| p.chars().count())
        .max()
        .unwrap_or(0)
        .max(MIN_PATH_WIDTH);
    // "GET/POST/PATCH/PUT/DELETE" (all 5 methods this crate's `methods`
    // array above ever produces) is 25 chars - the real worst case, not an
    // arbitrary round number.
    const MIN_METHODS_WIDTH: usize = 25;
    let methods_width = rows
        .iter()
        .map(|(_, m, _)| m.chars().count())
        .max()
        .unwrap_or(0)
        .max(MIN_METHODS_WIDTH);

    for (path, methods, description) in rows {
        println!("{path:<path_width$} {methods:<methods_width$} {description}");
    }
    Ok(())
}

/// Returns `Err` instead of exiting internally, same rationale as
/// `fetch_spec` - `main.rs` handles printing/exiting for both.
pub(crate) fn describe(spec: &Value, resource: &str) -> Result<(), String> {
    // Computed once and reused below - the binary name can't change
    // mid-invocation, so there's no reason to re-read std::env::args() and
    // re-allocate a path component twice in the same call.
    let bin = bin_name();
    // Accept either form (`selected_controls` or `/selected_controls`), but
    // normalize to the bare name for anything that isn't a spec path lookup
    // (skills::lookup, and the resource name embedded in hint messages) -
    // otherwise a slash-prefixed input silently misses the embedded skill
    // guidance and produces malformed hints like `//selected_controls`.
    let bare = resource.trim_start_matches('/');
    // Rejected explicitly rather than falling through to the spec lookup -
    // an empty or slash-only argument (`""`, `"/"`) would otherwise silently
    // normalize to the bare path `"/"`, producing a confusing "No resource
    // found at path /" instead of a message that names the actual problem.
    if bare.is_empty() {
        return Err(format!(
            "Resource name must not be empty. Run `{bin} resources` to see what's available."
        ));
    }
    // Rejected explicitly, same reasoning as the empty check above - a
    // multi-segment input like `selected_controls/123` would otherwise
    // normalize to `/selected_controls/123`, which can match a *member*
    // route in the spec. The logic below (look for a `get` operation, then
    // navigate its response schema) is written for collection routes, so
    // running it against a member-route entry produces misleading or
    // incomplete output rather than a clear "that's not a single resource
    // name" error.
    if bare.contains('/') {
        return Err(format!(
            "{resource:?} looks like a path with multiple segments; `describe` expects a single resource name (e.g. `selected_controls`). Run `{bin} resources` to see what's available."
        ));
    }
    let normalized = format!("/{bare}");
    let Some(path_obj) = spec.get("paths").and_then(|p| p.get(&normalized)) else {
        return Err(format!(
            "No resource found at path {normalized}. Run `{bin} resources` to see what's available."
        ));
    };

    let Some(get_op) = path_obj.get("get") else {
        println!("{normalized}: no GET operation (write-only or action route)");
        return Ok(());
    };

    let tag = operation_tag(get_op).unwrap_or_default();
    println!("{bare}\n");

    if let Some(skill) = crate::skills::lookup(bare) {
        println!("{}", skill.trim());
        println!("\n---\n");
    }

    println!("## API reference (live, from GET /openapi)\n");

    if let Some(description) = tag_description(spec, tag) {
        println!("{}\n", description.trim());
    } else {
        println!("(no tag description available)\n");
    }

    let attributes = data_properties(get_op)
        .and_then(|p| p.get("attributes"))
        .and_then(|a| a.get("properties"))
        .and_then(|p| p.as_object());

    if attributes.is_none() && uses_schema_composition(get_op) {
        // `println!` (stdout), not `eprintln!` - this is a completeness
        // caveat embedded in the middle of `describe`'s structured output,
        // not an error condition, so it needs to stay on the same stream as
        // the rest of that output or it goes missing/misordered when a
        // caller pipes stdout alone (e.g. `klaay describe ... | grep
        // attributes`).
        println!(
            "note: this resource's schema uses $ref/allOf/anyOf/oneOf, which this CLI doesn't resolve - attribute/relationship details below may be incomplete even though the spec has them.\n"
        );
    }

    if let Some(attrs) = attributes {
        // Sorted rather than left in the JSON object's parse order, which
        // varies across API responses (the server may reorder fields
        // between versions) - a stable order keeps `describe`'s output
        // diffable/scannable instead of shuffling non-deterministically.
        let mut names: Vec<&String> = attrs.keys().collect();
        names.sort();
        println!("known attributes (from a captured example response - not necessarily exhaustive, and doesn't distinguish creatable/updatable/read-only):");
        println!(
            "  {}",
            names
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let relationships = data_properties(get_op)
        .and_then(|p| p.get("relationships"))
        .and_then(|r| r.get("properties"))
        .and_then(|p| p.as_object());

    match relationships {
        Some(rels) if !rels.is_empty() => {
            println!("\nrelationships seen in a captured example (pass --include <name> to fetch; target type isn't always captured in the spec, so treat this as a starting point, not exhaustive):");
            // Sorted, for the same reason attributes are sorted above -
            // JSON object insertion order isn't guaranteed stable across
            // server versions, and an unsorted printout would make this
            // output non-deterministic and harder to diff run to run.
            let mut rel_names: Vec<&String> = rels.keys().collect();
            rel_names.sort();
            for name in rel_names {
                println!("  {name}");
            }
        }
        Some(_) => {
            println!("\nthe spec's captured example explicitly lists no relationships for this resource.");
        }
        None => {
            println!(
                "\nno relationships captured in the spec's example for this resource - it may still have some; try `{bin} get {bare} <id> --include <name>` with a guessed name, or check app/resources/{bare}_resource.rb in the Kiln source if you have it."
            );
        }
    }
    Ok(())
}

/// Navigates to the item-level `data` object in a GET operation's 200
/// response schema (before its own `properties` map) - shared by
/// `data_properties` and `uses_schema_composition` below.
fn data_item(operation: &Value) -> Option<&Value> {
    operation
        .get("responses")
        .and_then(|r| r.get("200"))
        .and_then(|r| r.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|c| c.get("schema"))
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.get("data"))
        .map(|d| d.get("items").unwrap_or(d))
}

/// Navigates to the `properties` of the item-level `data` object - shared by
/// the attributes and relationships lookups in `describe`, which only
/// diverge after this point.
fn data_properties(operation: &Value) -> Option<&serde_json::Map<String, Value>> {
    data_item(operation)
        .and_then(|d| d.get("properties"))
        .and_then(|p| p.as_object())
}

/// True when the item-level schema exists but expresses itself via one of
/// OpenAPI's composition keywords (`$ref`, `allOf`, `anyOf`, `oneOf`) instead
/// of an inline `properties` map - `data_properties` returns `None` for this
/// case too, indistinguishable from "no example captured" - this lets
/// `describe` at least tell the user which situation it is. Checks all four
/// keywords, not just `$ref`/`allOf` - a schema composed via `anyOf`/`oneOf`
/// would otherwise fall through both this check and `data_properties`,
/// leaving the user with unexplained empty output and no caveat at all.
fn uses_schema_composition(operation: &Value) -> bool {
    data_item(operation).is_some_and(|d| {
        d.get("$ref").is_some()
            || d.get("allOf").is_some()
            || d.get("anyOf").is_some()
            || d.get("oneOf").is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_list_marker_rejects_ordered_list_items() {
        assert!(is_ordered_list_marker("1. Records the result"));
        assert!(is_ordered_list_marker("10. Something else"));
        assert!(is_ordered_list_marker("1) Parenthesized item"));
    }

    #[test]
    fn ordered_list_marker_accepts_real_prose_starting_with_digits() {
        // Regression test: an earlier implementation used `str::split_once`
        // with a `!is_ascii_digit()` predicate, whose "after" half excludes
        // the matched delimiter - so a check for a leading "." or ")" on
        // that half could never succeed, making the whole ordered-list
        // rejection dead code that never actually fired.
        assert!(!is_ordered_list_marker("2FA is required"));
        assert!(!is_ordered_list_marker("3 parameters are accepted"));
        assert!(!is_ordered_list_marker("100.5 is a number"));
    }

    #[test]
    fn ordered_list_marker_rejects_non_digit_leading_punctuation() {
        assert!(!is_ordered_list_marker(". Some text"));
        assert!(!is_ordered_list_marker("Records the result"));
    }

    #[test]
    fn first_prose_line_skips_ordered_list_items() {
        let text = "1. Records the result of an audit\nThis is the real prose description.";
        assert_eq!(
            first_prose_line(text),
            "This is the real prose description."
        );
    }

    #[test]
    fn first_prose_line_keeps_prose_starting_with_a_digit() {
        let text = "2FA is required for all admin accounts.";
        assert_eq!(first_prose_line(text), text);
    }

    #[test]
    fn first_prose_line_skips_plus_marker_unordered_list_items() {
        // CommonMark's three valid unordered-list bullet characters are
        // `-`, `*`, and `+` - only the first two were handled before.
        let text = "+ Records the result of an audit\nThis is the real prose description.";
        assert_eq!(
            first_prose_line(text),
            "This is the real prose description."
        );
    }

    #[test]
    fn first_prose_line_skips_horizontal_rules() {
        for rule in ["---", "===", "***", "----", "===="] {
            let text = format!("{rule}\nReal prose.");
            assert_eq!(first_prose_line(&text), "Real prose.", "failed for: {rule}");
        }
    }

    #[test]
    fn first_prose_line_requires_at_least_three_chars_for_a_rule() {
        // Exactly 2 of the same char is below `is_rule`'s 3-char minimum, and
        // (unlike a bare single "-"/"*"/"+", which the separate bullet-marker
        // check below rejects for an unrelated reason) isn't caught by any
        // other check either - so it's real prose, not a rule.
        for text in ["--", "=="] {
            assert_eq!(first_prose_line(text), text, "wrongly skipped: {text}");
        }
    }

    #[test]
    fn first_prose_line_skips_a_bare_single_bullet_marker() {
        // A lone "-"/"*"/"+" (no text after it) is rejected by the dedicated
        // bare-marker check, not by `is_rule` (which needs 3+) - distinct
        // from the horizontal-rule case above, so tested separately.
        for text in ["-", "*", "+"] {
            assert_eq!(first_prose_line(text), "", "wrongly kept: {text}");
        }
    }

    #[test]
    fn first_prose_line_skips_headings_tables_fences_blockquotes_and_bullets() {
        for skipped in [
            "# Heading",
            "## H2",
            "| col1 | col2 |",
            "```rust",
            "> quote",
            "- item",
            "* item",
        ] {
            let text = format!("{skipped}\nReal prose.");
            assert_eq!(
                first_prose_line(&text),
                "Real prose.",
                "failed for: {skipped}"
            );
        }
    }
}
