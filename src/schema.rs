// SPDX-License-Identifier: GPL-3.0-or-later
use crate::client::{ApiClient, HttpMethod};
use crate::config::{bin_name, openapi_cache_path};
use serde_json::Value;
use std::fs;
use std::io::{BufWriter, Write};

/// Fetches GET /openapi (authenticated) and caches it locally. The spec is
/// Kiln's own generated OpenAPI document, so this reflects the live API.
/// Returns `Err` on failure; `main.rs` handles printing/exiting.
pub(crate) fn fetch_spec(client: &ApiClient, force_refresh: bool) -> Result<Value, String> {
    // No home directory to cache under - just live-fetch;
    // `resources`/`describe` work fine without a cache, just slower.
    let cache_path = openapi_cache_path();
    if !force_refresh {
        if let Some(path) = &cache_path {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(mut cached) = serde_json::from_str::<Value>(&contents) {
                    // The cache is one shared file across `--api-url` values,
                    // so it's keyed by `api_url`: switching environments must
                    // not serve the previous environment's schema. Older cache
                    // files without an `api_url` key are always treated as
                    // stale.
                    let cached_api_url = cached.get("api_url").and_then(|v| v.as_str());
                    if cached_api_url == Some(client.base_url_trimmed()) {
                        // `.take()`, not `.clone()` - `cached` is dropped right
                        // after this block, so move the (potentially
                        // multi-megabyte) spec out instead of deep-copying it.
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
            // `error_detail()` distinguishes a JSON-parse failure from a
            // genuinely empty body, which re-serializing `raw_body()` cannot.
            response.error_detail()
        ));
    }
    // The whole cache-write attempt is Unix-only (nothing here is created or
    // read on non-Unix - see the non-Unix note below), gated as one block so
    // Windows doesn't create the config directory it never writes to.
    #[cfg(unix)]
    if let Some(cache_path) = &cache_path {
        if let Some(dir) = cache_path.parent() {
            // 0700 (owner-only), matching `token_store.rs`'s `save_to_file`.
            // This shared `~/.config/klaay` directory may not exist yet (a
            // keyring machine never writes a token file), so if
            // `resources`/`describe` creates it first, a plain
            // `create_dir_all` would leave it world-readable per the umask.
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
                // Unconditional - `DirBuilder`'s `mode` only applies when it
                // creates the directory, so a pre-existing one needs this to
                // get tightened.
                if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
                    eprintln!(
                        "Warning: could not tighten permissions on cache directory {}: {e}",
                        dir.display()
                    );
                }
                remove_stale_cache_temp_files(dir);
                // Sibling temp file, renamed atomically over the real path, so
                // an interrupted write can't leave a truncated cache for a
                // concurrent reader. Mixes pid with a nanosecond timestamp
                // since pids are reused and could otherwise collide.
                let unique = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_else(|_| {
                        // Clock before the epoch (broken/skewed clock) - a
                        // fixed fallback would collide across processes, so use
                        // a process-local counter, unique per call and, with
                        // the pid, across processes.
                        static FALLBACK: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(1);
                        u128::from(FALLBACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    });
                let tmp_path = cache_path
                    .with_file_name(format!("openapi-cache-{}-{unique}.tmp", std::process::id()));
                // `0o600` - matches `token_store.rs`'s credential files rather
                // than resting on the umask; the cache holds the `api_url` and
                // full spec. `create_new` (not `File::create`) fails loudly on
                // a name collision instead of silently truncating.
                use std::os::unix::fs::OpenOptionsExt;
                let write_result = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp_path)
                    .and_then(|file| {
                        let mut writer = BufWriter::new(file);
                        // Explicit flush (and error propagation) rather than
                        // BufWriter's flush-on-drop, which discards failures:
                        // `to_writer` can return `Ok` with bytes still buffered,
                        // and the rename below would then promote a truncated
                        // file. Serialized field-by-field (not via `json!`) to
                        // avoid cloning the whole spec tree just to serialize
                        // it; `api_url` is stored so the read path can reject a
                        // different environment's cache.
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
                    // `tmp_path`, not `cache_path` - the failed operation was
                    // against the temp file.
                    eprintln!(
                        "Warning: could not write spec cache to {}: {e}",
                        tmp_path.display()
                    );
                    // Cleanup skipped on `AlreadyExists`: with `create_new`,
                    // that means the file exists, and the stale-scan above
                    // guarantees it's under an hour old - so it belongs to
                    // another concurrent writer, not this call. Every other
                    // error kind means this call created the file.
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
    // Non-Unix: no caching (can't control the file's permissions, same
    // reasoning as `token_store.rs`'s `atomic_write_secure`). The next call
    // just live-fetches, so there's nothing to warn about.
    Ok(response.into_raw_body())
}

/// Best-effort cleanup of `openapi-cache-*.tmp` files left by a process killed
/// mid-write, which would otherwise accumulate. Only removes files older than
/// an hour, so a temp file another invocation is actively writing is untouched.
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
        // Require the portion between `prefix` and `.tmp` to match this crate's
        // own `{pid}-{unique}` naming (digits, exactly one hyphen) so a
        // same-prefix file another tool dropped here (e.g.
        // `openapi-cache-editor-backup.tmp`) isn't deleted.
        let middle = &name[prefix.len()..name.len() - suffix.len()];
        if middle.is_empty()
            || !middle.chars().all(|c| c.is_ascii_digit() || c == '-')
            || middle.chars().filter(|&c| c == '-').count() != 1
            || middle.starts_with('-')
            || middle.ends_with('-')
        {
            continue;
        }
        // A future `modified` (clock skew, NTP correction, cross-host copy) is
        // checked against `STALE_AFTER` in the other direction rather than
        // treated as unconditionally stale, so a file another process is
        // actively writing a few minutes ahead isn't deleted. `symlink_metadata`
        // (non-following) is used for both this and the type guard below so
        // they agree on the same entry - `entry.metadata()` would follow a
        // symlink for the mtime but `entry.file_type()` wouldn't for the type.
        let symlink_meta = entry.path().symlink_metadata().ok();
        let is_stale = match symlink_meta.as_ref().and_then(|m| m.modified().ok()) {
            Some(modified) => match std::time::SystemTime::now().duration_since(modified) {
                Ok(age) => age > STALE_AFTER,
                Err(e) => e.duration() > STALE_AFTER,
            },
            None => false,
        };
        // Regular files only - the scan should only ever remove temp files it
        // created, not follow a symlink.
        let is_regular_file = symlink_meta.as_ref().map(|m| m.is_file()).unwrap_or(false);
        if is_stale && is_regular_file {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// A resource's generated tag description - where Kiln's filters/sortable-fields
/// tables live (see the kiln-openapi skill), not in per-parameter metadata.
fn tag_description<'a>(spec: &'a Value, tag_name: &str) -> Option<&'a str> {
    spec.get("tags")?
        .as_array()?
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(tag_name))
        .and_then(|t| t.get("description"))
        .and_then(|d| d.as_str())
}

/// Up to 5 collection resource names resembling `query`, for "did you mean"
/// hints when a lookup misses. Matches by substring either way, case-folded
/// and with a trailing `s` trimmed so singular input (`control`) reaches
/// `selected_controls`.
fn suggest_resources(spec: &Value, query: &str) -> Vec<String> {
    let q = query.to_ascii_lowercase();
    // Strip at most one trailing `s` (the plural suffix) - `trim_end_matches`
    // would over-strip `access` -> `acce`, corrupting the substring match.
    let q_singularish = q.strip_suffix('s').unwrap_or(&q);
    let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let matches = paths
        .keys()
        .filter_map(|path| path.strip_prefix('/'))
        // Collection routes only; member/nested paths aren't valid `describe`
        // arguments. A root `"/"` strips to `""` - drop it explicitly rather than
        // rely on the length guards below to filter an empty name out.
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .filter(|name| {
            let n = name.to_ascii_lowercase();
            let n_singularish = n.strip_suffix('s').unwrap_or(&n);
            // Both needles need >= 2 chars: `contains` on a 0- or 1-char needle
            // matches almost everything, flooding the hints for a typo like `a`.
            (q_singularish.len() >= 2 && n.contains(q_singularish))
                || (n_singularish.len() >= 2 && q.contains(n_singularish))
        });
    // Rank shortest first (common resources outrank long generated join names),
    // then prefix matches ahead of mid-string ones. The case-insensitive prefix
    // test compares bytes directly, with no per-element lowercase allocation
    // (`q_singularish` is already lowercased ASCII, as are resource names).
    let mut ranked: Vec<(usize, bool, &str)> = matches
        .map(|name| {
            // Prefix in either direction, mirroring the two-directional filter
            // above: the resource name starts with the query, or the query
            // starts with the resource name. Compared byte-wise via
            // `eq_ignore_ascii_case` - no lowercase allocation. `n_len` drops one
            // trailing `s` (resource names are lowercase, so the byte check is
            // enough).
            let n_len = name.len() - usize::from(name.ends_with('s'));
            let is_prefix = name
                .as_bytes()
                .get(..q_singularish.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(q_singularish.as_bytes()))
                || q.as_bytes()
                    .get(..n_len)
                    .is_some_and(|p| p.eq_ignore_ascii_case(&name.as_bytes()[..n_len]));
            (name.len(), !is_prefix, name)
        })
        .collect();
    // `name` as a tertiary key so ties on (len, not_prefix) are ordered
    // deterministically (alphabetically) rather than by unstable-sort chance.
    ranked.sort_unstable_by_key(|&(len, not_prefix, name)| (len, not_prefix, name));
    ranked.truncate(5);
    ranked
        .into_iter()
        .map(|(_, _, name)| name.to_string())
        .collect()
}

/// Which of the two auto-generated single-column tables is currently being
/// captured (their rows feed `describe`'s merged filter/sort output rather than
/// printing raw). `Off` means any other line prints as-is. Named `Off` rather
/// than `None` to avoid visual collision with `Option::None`.
enum Capturing {
    Off,
    Filters,
    Sortable,
}

/// Prints a tag description's prose (and any curated tables) to stdout while
/// capturing the two auto-generated single-column tables (`Filters`,
/// `Sortable Fields`) as `(filters, sortable_fields)`, so `describe` can merge
/// them with the structured `parameters` instead of dumping them raw.
fn render_tag_description(text: &str) -> (Vec<String>, Vec<String>) {
    let mut filters = Vec::new();
    let mut sortable = Vec::new();
    let mut capturing = Capturing::Off;
    // So a structurally-empty description doesn't emit a lone trailing newline.
    let mut printed = false;
    for line in text.lines() {
        let trimmed = line.trim();
        // A row either starts with `|` (standard markdown) or - only while we're
        // already inside one of Kiln's tables - ends with `|`: its generator
        // emits continuation rows like `state_include |` with no leading pipe.
        // Gating the trailing-pipe case on `capturing` means ordinary prose that
        // merely ends with `|` outside a table is printed as prose, not
        // captured. Any non-row line ends the capture (blank lines are
        // collapsed, not printed).
        let is_table_row = trimmed.starts_with('|')
            || (!matches!(capturing, Capturing::Off) && trimmed.ends_with('|'));
        if !is_table_row {
            capturing = Capturing::Off;
            if !trimmed.is_empty() {
                println!("{}", strip_markdown_link(trimmed));
                printed = true;
            }
            continue;
        }
        if is_separator_row(trimmed) {
            continue;
        }
        let cells: Vec<String> = trimmed
            .trim_matches(|c| c == '|' || c == ' ')
            .split('|')
            .map(|c| strip_markdown_link(c.trim()))
            .filter(|c| !c.is_empty())
            .collect();
        if cells.is_empty() {
            continue;
        }
        // Check for a special-table header first, whatever the current state, so
        // a second auto-generated table that follows the first with no blank
        // line between them (`| Sortable Fields |` right after the filter rows)
        // switches capture instead of being captured as a filter value.
        if let Some(next) = special_table_header(&cells) {
            capturing = next;
        } else {
            match capturing {
                // Single-column table: only the first cell is the value; any
                // extra cells in a malformed multi-column row are intentionally
                // ignored. A real filter/sort field name is a bare identifier
                // (`[A-Za-z0-9_]`), so a row that isn't one - a `Note: ... |`
                // line, a `foo:|` token - is prose: end the table and print it
                // rather than capturing garbage. (Kiln separates its tables from
                // prose with a blank line, so this is a belt-and-braces guard
                // against a malformed/hand-written description.)
                Capturing::Filters | Capturing::Sortable => {
                    let is_filters = matches!(capturing, Capturing::Filters);
                    let cell = cells
                        .into_iter()
                        .next()
                        .expect("cells is non-empty; guarded above");
                    if !cell.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        // Prose - end the table and print the whole line
                        // (link-stripped), not just the first split cell. Strip the
                        // outer pipes/spaces first: this row qualified as a table
                        // row so it may still carry a trailing `|`, unlike the
                        // top-level prose path (which only fires on non-`|` rows).
                        capturing = Capturing::Off;
                        println!(
                            "{}",
                            strip_markdown_link(trimmed.trim_matches(|c| c == '|' || c == ' '))
                        );
                        printed = true;
                    } else if is_filters {
                        filters.push(cell);
                    } else {
                        sortable.push(cell);
                    }
                }
                // Not inside a table and not a special header: a curated table
                // row, printed verbatim.
                Capturing::Off => {
                    println!("{}", cells.join(" | "));
                    printed = true;
                }
            }
        }
    }
    if printed {
        println!();
    }
    (filters, sortable)
}

/// The special single-column table a header row names, if any. Recognizing this
/// regardless of current capture state lets two auto-generated tables sit
/// back-to-back without a blank line and still parse correctly.
fn special_table_header(cells: &[String]) -> Option<Capturing> {
    match cells {
        [header] if header.eq_ignore_ascii_case("filters") => Some(Capturing::Filters),
        [header] if header.eq_ignore_ascii_case("sortable fields") => Some(Capturing::Sortable),
        _ => None,
    }
}

/// A markdown table's alignment row (every cell is only `-`/`:`, e.g.
/// `| --- | :---: |`). Checked per cell after splitting on `|`, so a real data
/// row is never mistaken for a separator just because it sits between pipes.
fn is_separator_row(row: &str) -> bool {
    let inner = row.trim_matches(|c| c == '|' || c == ' ');
    // An otherwise-empty row (just pipes/spaces) isn't a separator.
    if inner.is_empty() {
        return false;
    }
    // A blank cell is allowed (CommonMark accepts `| --- | |`); it just isn't
    // what disqualifies the row - only a cell with non-`-`/`:` content does.
    inner.split('|').all(|cell| {
        let cell = cell.trim();
        // A non-empty separator cell needs at least one `-` (CommonMark) - an
        // all-colons cell like `:::` is a data value, not a separator.
        cell.is_empty() || (cell.contains('-') && cell.chars().all(|c| matches!(c, '-' | ':')))
    })
}

/// A collection GET's `filter[...]` query params from the structured OpenAPI
/// `parameters`, keyed by inner name (`state_include` from
/// `filter[state_include]`). `true` = array-typed: repeat `--filter k=v` to
/// pass multiple values; `false` = scalar. Only the params some captured
/// example actually sent appear here, which is why it's merged with the
/// complete-but-untyped markdown filter table rather than used alone.
fn structured_filter_types(get_op: &Value) -> std::collections::BTreeMap<String, bool> {
    let mut out = std::collections::BTreeMap::new();
    let Some(params) = get_op.get("parameters").and_then(|p| p.as_array()) else {
        return out;
    };
    for p in params {
        if p.get("in").and_then(Value::as_str) != Some("query") {
            continue;
        }
        let Some(inner) = p
            .get("name")
            .and_then(Value::as_str)
            .and_then(|n| n.strip_prefix("filter["))
            .and_then(|n| n.strip_suffix(']'))
        else {
            continue;
        };
        let is_array = p
            .get("schema")
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            == Some("array");
        // Lowercased so keys line up with `print_query_surface`, which
        // lowercases every filter name before looking its type up here.
        out.insert(inner.to_ascii_lowercase(), is_array);
    }
    out
}

/// `[Filters](#tag/Filter)` -> `Filters`. The anchors only resolve in the API
/// docs site, so the link syntax is noise in terminal output. Only well-formed
/// `[label](url)` spans collapse; a bare reference like `[RFC 7231]` or an
/// orphaned `](` is left intact, and scanning continues past it so later real
/// links in the same string still collapse.
fn strip_markdown_link(cell: &str) -> String {
    let mut out = cell.to_string();
    let mut from = 0;
    while let Some(rel_mid) = out[from..].find("](") {
        let mid = from + rel_mid;
        // The nearest `[` before this `](` opens the label. None, or a label
        // that itself contains `](` (so we'd be pairing the wrong brackets),
        // means this `](` is orphaned - skip past it and keep scanning.
        let Some(open) = out[from..mid].rfind('[').map(|i| from + i) else {
            from = mid + 2;
            continue;
        };
        if out[open + 1..mid].contains("](") {
            from = mid + 2;
            continue;
        }
        // Close on the first `)` after `](`; a `)` inside the label is safe
        // since the search starts past `](`. No `)` at all: this `](` is
        // malformed, so skip past it and keep scanning for later valid links.
        let url_start = mid + 2;
        let Some(rel_close) = out[url_start..].find(')') else {
            from = url_start;
            continue;
        };
        let close = url_start + rel_close;
        let label = out[open + 1..mid].to_string();
        out.replace_range(open..=close, &label);
        from = open + label.len();
    }
    out
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

/// Prints the mergeable query surface (filters + sortable fields) for a
/// collection GET. Structured-first: each filter's array-vs-scalar type comes
/// from the OpenAPI `parameters` where the spec has it (reliable typing for
/// the `--filter k=v` bracket encoding); the complete filter/sort set comes
/// from the markdown tables, which enumerate every scope even when no captured
/// example exercised it. Filters the structured spec omits are still listed,
/// just without a type.
fn print_query_surface(get_op: &Value, md_filters: &[String], md_sortable: &[String]) {
    let structured = structured_filter_types(get_op);

    // Lowercase before deduping: markdown cells and the structured `filter[..]`
    // parameter names are both lowercase snake_case in practice, but normalizing
    // makes that invariant explicit so a stray `State_Include` couldn't list the
    // same filter twice (once typed, once not).
    let mut names: Vec<String> = md_filters
        .iter()
        .chain(structured.keys())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    names.sort_unstable();
    names.dedup();

    if !names.is_empty() {
        println!("filters (pass with `--filter <name>=<value>`):");
        for name in &names {
            match structured.get(name.as_str()) {
                Some(true) => {
                    println!(
                        "  {name} [array; repeat --filter {name}=<value> for multiple values]"
                    );
                }
                Some(false) => println!("  {name} [scalar]"),
                None => println!("  {name}"),
            }
        }
        println!();
    }

    if !md_sortable.is_empty() {
        println!("sortable fields (pass with `--sort <field>`, `-` prefix for descending):");
        println!("  {}\n", md_sortable.join(", "));
    }
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
        let hint = match suggest_resources(spec, bare) {
            candidates if candidates.is_empty() => String::new(),
            candidates => format!(" Did you mean: {}?", candidates.join(", ")),
        };
        return Err(format!(
            "No resource found at path {normalized}.{hint} Run `{bin} resources` to see everything available."
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

    let (md_filters, md_sortable) = match tag_description(spec, tag) {
        Some(description) => render_tag_description(description),
        None => {
            println!("(no tag description available)\n");
            (Vec::new(), Vec::new())
        }
    };

    print_query_surface(get_op, &md_filters, &md_sortable);

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

    #[test]
    fn strip_markdown_link_unwraps_label_and_leaves_plain_text_alone() {
        assert_eq!(strip_markdown_link("[Filters](#tag/Filter)"), "Filters");
        assert_eq!(strip_markdown_link("Sortable Fields"), "Sortable Fields");
        // Prose with several inline links - every one collapses to its label.
        assert_eq!(
            strip_markdown_link("see [controls](/#tag/Control) and a [vendor](/#tag/Vendor)."),
            "see controls and a vendor."
        );
        // A stray `[` before a real link must not pair with the link's `](` -
        // the reference bracket is left intact and only the real link folds.
        assert_eq!(
            strip_markdown_link("[RFC 7231] see [spec](url)"),
            "[RFC 7231] see spec"
        );
        // A `)` inside the label doesn't terminate the target early.
        assert_eq!(strip_markdown_link("[a) b](url)"), "a) b");
        // Malformed link syntax (no closing paren) passes through unchanged
        // rather than producing a mangled slice.
        assert_eq!(strip_markdown_link("[Filters](#tag"), "[Filters](#tag");
    }

    #[test]
    fn suggest_resources_matches_singular_input_and_prefers_short_names() {
        let spec = serde_json::json!({
            "paths": {
                "/selected_controls": {},
                "/control_templates": {},
                "/control_template_required_policy_templates": {},
                "/selected_controls/{id}": {},
                "/policies": {}
            }
        });
        let suggestions = suggest_resources(&spec, "control");
        // Singular input matches; member routes excluded. `control_templates`
        // and `selected_controls` are both 17 chars, so length ties - the
        // prefix-match tiebreaker (`starts_with("control")`) orders the former
        // first; the 42-char join name comes last on length alone.
        assert_eq!(
            suggestions,
            vec![
                "control_templates".to_string(),
                "selected_controls".to_string(),
                "control_template_required_policy_templates".to_string(),
            ]
        );
        assert_eq!(suggest_resources(&spec, "zzz"), Vec::<String>::new());
    }

    #[test]
    fn structured_filter_types_reads_bracketed_query_params_only() {
        let op = serde_json::json!({
            "parameters": [
                { "name": "Authorization", "in": "header", "schema": { "type": "string" } },
                { "name": "filter[state_include]", "in": "query", "schema": { "type": "array" } },
                { "name": "filter[search]", "in": "query", "schema": { "type": "string" } },
                { "name": "sort", "in": "query", "schema": { "type": "string" } },
                { "name": "resource_type", "in": "path", "schema": { "type": "string" } }
            ]
        });
        let types = structured_filter_types(&op);
        assert_eq!(types.get("state_include"), Some(&true));
        assert_eq!(types.get("search"), Some(&false));
        // Non-filter query params (sort) and non-query params are excluded.
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn render_tag_description_captures_filter_and_sortable_tables() {
        let text = "Some prose.\n\n\
            | [Filters](#tag/Filter) |\n| ------ |\n| search |\nstate_include |\n\n\
            | Sortable Fields |\n| ------ |\n| name |\ncreated_at |";
        let (filters, sortable) = render_tag_description(text);
        assert_eq!(filters, vec!["search", "state_include"]);
        assert_eq!(sortable, vec!["name", "created_at"]);
    }

    #[test]
    fn suggest_resources_does_not_flood_on_a_short_query() {
        let spec = serde_json::json!({
            "paths": { "/selected_controls": {}, "/policies": {}, "/vendors": {} }
        });
        // "s" strips to "", and "e" is a 1-char needle that does not strip -
        // both are below the >= 2 length floor, so neither matches everything.
        assert_eq!(suggest_resources(&spec, "s"), Vec::<String>::new());
        assert_eq!(suggest_resources(&spec, "e"), Vec::<String>::new());
    }

    #[test]
    fn strip_markdown_link_keeps_scanning_past_an_orphaned_delimiter() {
        // A stray `](` with no opening `[` is left intact, and the real link
        // after it still collapses.
        assert_eq!(
            strip_markdown_link("a](b) then [real](url)"),
            "a](b) then real"
        );
    }

    #[test]
    fn render_tag_description_handles_back_to_back_tables_without_blank_line() {
        // The Sortable Fields table follows the Filters table with no blank line
        // between them; the header must switch capture, not become a filter.
        let text = "| Filters |\n| --- |\n| search |\n| Sortable Fields |\n| --- |\n| name |";
        let (filters, sortable) = render_tag_description(text);
        assert_eq!(filters, vec!["search"]);
        assert_eq!(sortable, vec!["name"]);
    }

    #[test]
    fn render_tag_description_rejects_non_identifier_row_inside_a_table() {
        // A whitespace-free but non-identifier token (`foo:` has a colon) inside
        // a Filters block isn't a field name, so it isn't captured.
        let text = "| Filters |\n| --- |\n| search |\nfoo: |";
        let (filters, _sortable) = render_tag_description(text);
        assert_eq!(filters, vec!["search"]);
    }

    #[test]
    fn render_tag_description_stops_capturing_at_spacey_prose_inside_a_table() {
        // A pipe-terminated prose line inside a Filters block isn't a field
        // name (it has spaces), so it ends capture instead of being captured.
        let text = "| Filters |\n| --- |\n| search |\nNote: values must match |\nstate_include |";
        let (filters, _sortable) = render_tag_description(text);
        assert_eq!(filters, vec!["search"]);
    }

    #[test]
    fn render_tag_description_treats_pipe_terminated_prose_as_prose() {
        // A prose line that merely ends with `|`, outside any table, is not
        // mistaken for a filter/sort row (the trailing-pipe case only counts
        // while already capturing a table).
        let text = "See the filter table for details |";
        let (filters, sortable) = render_tag_description(text);
        assert!(filters.is_empty());
        assert!(sortable.is_empty());
    }

    #[test]
    fn render_tag_description_prints_curated_multi_column_rows_verbatim() {
        // A curated table (not one of the two auto-generated single-column
        // ones) prints its rows rather than being captured or garbled, and the
        // filter/sortable outputs stay empty.
        let text = "| Filter | Type |\n| --- | --- |\n| search | string |";
        let (filters, sortable) = render_tag_description(text);
        assert!(filters.is_empty());
        assert!(sortable.is_empty());
    }
}
