// SPDX-License-Identifier: GPL-3.0-or-later
use crate::client::ApiClient;
use crate::config::{bin_name, openapi_cache_path};
use serde_json::Value;
use std::fs;
use std::io::{BufWriter, Write};

/// Fetches `/openapi.json` from the docs site and caches it locally. `client`
/// points at the docs site and carries the user's token (see
/// `Config::spec_source`). Returns `Err` on failure; `main.rs` handles
/// printing/exiting.
pub(crate) fn fetch_spec(client: &ApiClient, force_refresh: bool) -> Result<Value, String> {
    // No home directory to cache under - just live-fetch;
    // `resources`/`describe` work fine without a cache, just slower.
    let cache_path = openapi_cache_path();
    if !force_refresh {
        if let Some(path) = &cache_path {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(mut cached) = serde_json::from_str::<Value>(&contents) {
                    // The cache is one shared file across docs sites, so it's
                    // keyed by `docs_url`: switching sites must not serve the
                    // previous site's schema. A cache file without that key is
                    // stale.
                    let cached_docs_url = cached.get("docs_url").and_then(|v| v.as_str());
                    if cached_docs_url == Some(client.base_url_trimmed()) {
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

    let url = format!("{}/openapi.json", client.base_url_trimmed());
    let response = client.get_without_redirects("/openapi.json");
    // The docs site sends a request it does not accept to the sign-in page.
    if response.status == 302 {
        return Err(format!(
            "Could not fetch {url}: the docs site did not accept your token. Run `{} login` again.",
            bin_name()
        ));
    }
    if !response.is_success() {
        return Err(format!(
            "Could not fetch {url} ({}): {}",
            response.status,
            // `error_detail()` distinguishes a JSON-parse failure from a
            // genuinely empty body, which re-serializing `raw_body()` cannot.
            response.error_detail()
        ));
    }
    // Before the cache write, so a wrong page is never cached.
    require_paths(response.raw_body()).map_err(|e| format!("Could not read {url}: {e}"))?;
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
                // than resting on the umask; the cache holds the `docs_url` and
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
                        // it; `docs_url` is stored so the read path can reject a
                        // different site's cache.
                        use serde::ser::SerializeMap;
                        use serde::Serializer as _;
                        serde_json::Serializer::new(&mut writer)
                            .serialize_map(Some(2))
                            .and_then(|mut map| {
                                map.serialize_entry("docs_url", client.base_url_trimmed())?;
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

fn require_paths(spec: &Value) -> Result<(), String> {
    match spec.get("paths").and_then(Value::as_object) {
        Some(_) => Ok(()),
        None => Err("Spec has no paths".to_string()),
    }
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

/// A collection GET's `filter[...]` query params from the structured OpenAPI
/// `parameters`, keyed by inner name (`state_include` from
/// `filter[state_include]`). `true` = array-typed: repeat `--filter k=v` to
/// pass multiple values; `false` = scalar.
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
        out.insert(inner.to_string(), is_array);
    }
    out
}

/// The sortable fields of a collection GET. Kiln lists them in the `sort`
/// parameter's description, after "Sortable: ".
fn sortable_fields(get_op: &Value) -> Vec<&str> {
    get_op
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("name").and_then(Value::as_str) == Some("sort"))
        .filter_map(|p| p.get("description").and_then(Value::as_str))
        .filter_map(|d| d.split_once("Sortable: "))
        .flat_map(|(_, list)| list.trim_end_matches('.').split(", "))
        .collect()
}

/// Prints the filters and sortable fields of a collection GET.
fn print_query_surface(get_op: &Value) {
    let filters = structured_filter_types(get_op);
    if !filters.is_empty() {
        println!("filters (pass with `--filter <name>=<value>`):");
        for (name, is_array) in &filters {
            if *is_array {
                println!("  {name} [array; repeat --filter {name}=<value> for multiple values]");
            } else {
                println!("  {name} [scalar]");
            }
        }
        println!();
    }

    let sortable = sortable_fields(get_op);
    if !sortable.is_empty() {
        println!("sortable fields (pass with `--sort <field>`, `-` prefix for descending):");
        println!("  {}\n", sortable.join(", "));
    }
}

/// Returns `Err` instead of printing and returning silently, same rationale
/// as `fetch_spec`/`describe` - without this, `main.rs` had no way to
/// distinguish a genuinely empty spec's success from this "spec has no
/// paths" degraded case, so a script checking `$?` after `klaay resources`
/// would see exit code 0 either way.
fn resource_rows(spec: &Value) -> Result<Vec<(String, String, String)>, String> {
    require_paths(spec)?;
    let paths = spec["paths"].as_object().expect("require_paths checked it");

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
        let description = op
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        rows.push((path.clone(), methods.join("/"), description));
    }
    // Sorted by path alone, not the whole (path, methods, description) tuple -
    // the user's mental model is a sorted list of paths, so ordering driven
    // by description text (whenever two paths happen to share a prefix)
    // would be confusing.
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rows)
}

pub(crate) fn list_resources(spec: &Value) -> Result<(), String> {
    let rows = resource_rows(spec)?;

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

    println!("{bare}\n");

    if let Some(skill) = crate::skills::lookup(bare) {
        println!("{}", skill.trim());
        println!("\n---\n");
    }

    println!("## API reference (from the docs site's openapi.json)\n");

    print_query_surface(get_op);

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
    fn sortable_fields_come_from_the_sort_parameter_description() {
        let op = serde_json::json!({
            "parameters": [{
                "name": "sort", "in": "query",
                "description": "Comma-separated sort fields; prefix a field with `-` for descending. Sortable: name, created_at."
            }]
        });
        assert_eq!(sortable_fields(&op), vec!["name", "created_at"]);
    }

    #[test]
    fn sortable_fields_are_empty_without_a_described_sort_parameter() {
        for op in [
            serde_json::json!({}),
            serde_json::json!({ "parameters": [{ "name": "sort", "in": "query" }] }),
        ] {
            assert!(sortable_fields(&op).is_empty(), "{op}");
        }
    }

    #[test]
    fn resource_rows_describe_a_resource_with_its_operation_summary() {
        let spec = serde_json::json!({
            "paths": {
                "/vendors": { "get": { "summary": "List vendors" }, "post": {} },
                "/vendors/{id}": { "get": { "summary": "Get a vendor" } }
            }
        });
        assert_eq!(
            resource_rows(&spec).unwrap(),
            vec![(
                "/vendors".to_string(),
                "GET/POST".to_string(),
                "List vendors".to_string()
            )]
        );
    }

    #[test]
    fn spec_from_response_rejects_a_document_with_no_paths() {
        let page = serde_json::json!({ "title": "not an API description" });
        assert!(require_paths(&page).is_err());
        assert!(require_paths(&serde_json::json!({ "paths": {} })).is_ok());
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

    /// Answers one request on a local port with `response`.
    fn docs_site(response: &'static str) -> ApiClient {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });
        ApiClient::new(url, Some(zeroize::Zeroizing::new("a.b.c".to_string())))
    }

    #[test]
    fn a_sign_in_redirect_says_the_docs_site_refused_the_token() {
        let client = docs_site(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let err = fetch_spec(&client, true).unwrap_err();
        assert!(err.contains("did not accept your token"), "{err}");
    }

    #[test]
    fn a_page_that_is_not_an_api_description_is_an_error() {
        let client = docs_site(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
        let err = fetch_spec(&client, true).unwrap_err();
        assert!(err.contains("Spec has no paths"), "{err}");
    }
}
