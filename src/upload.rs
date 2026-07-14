use crate::client::ApiClient;
use crate::format::json_type_name;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Extensions accepted by Kiln's upload pipeline - not a 1:1 mirror of
/// PERMITTED_FILE_TYPES (apps/kiln/app/models/concerns/attachments.rb): it's
/// that default allow-list's extensions, plus MIME types some specific model
/// override additionally accepts (e.g. `application/vnd.ms-excel` for
/// `UserImport#source`, which isn't in PERMITTED_FILE_TYPES at all), minus
/// `text/xml` (in PERMITTED_FILE_TYPES, but deliberately omitted here - see
/// the comment below). A generic MIME-guessing crate can't express this
/// "default plus overrides minus one" shape, so it's an explicit table
/// instead, since the server rejects anything outside its actual accepted
/// set regardless of what a guess would produce. `None` for an unrecognized
/// extension, rather than a fallback guess like `application/octet-stream` -
/// a guess here would just be rejected server-side after a full upload
/// round-trip; the caller exits with a clear message instead.
fn content_type_for(path: &Path) -> Option<&'static str> {
    // Table + `eq_ignore_ascii_case`, not `.to_lowercase()` - every
    // extension here is ASCII-only, so lowercasing into a fresh heap
    // `String` just to immediately match against it (and then discard the
    // allocation) was unnecessary; case-insensitive comparison against the
    // raw `&str` is both cheaper and consistent with how header names are
    // already compared elsewhere in this file.
    // `text/xml` is in the server's PERMITTED_FILE_TYPES alongside
    // `application/xml` (attachments.rb) but deliberately has no entry here -
    // there's no extension in real use that conventionally means `text/xml`
    // specifically rather than `application/xml` (`.xml` itself maps below to
    // `application/xml`, already accepted), and guessing one (e.g. `.xsl`,
    // `.xhtml`) would invent a convention not established anywhere in this
    // codebase. A file that must upload as exactly `text/xml` isn't reachable
    // through this table - use `klaay call` directly if that's ever needed.
    const EXTENSIONS: &[(&str, &str)] = &[
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("webp", "image/webp"),
        ("gif", "image/gif"),
        ("svg", "image/svg+xml"),
        ("bmp", "image/bmp"),
        ("tif", "image/tiff"),
        ("tiff", "image/tiff"),
        ("pdf", "application/pdf"),
        ("json", "application/json"),
        ("xml", "application/xml"),
        ("zip", "application/zip"),
        (
            "xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        // Legacy Excel format - `UserImport#source` (apps/kiln/app/models/
        // user_import.rb) explicitly permits this content type alongside
        // the modern `.xlsx` one and CSV, so a `.xls` file would otherwise
        // be rejected client-side as "unrecognized extension" even though
        // the server accepts it.
        ("xls", "application/vnd.ms-excel"),
        ("csv", "text/csv"),
        ("md", "text/markdown"),
        ("txt", "text/plain"),
    ];
    let raw_ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    EXTENSIONS
        .iter()
        .find(|(ext, _)| ext.eq_ignore_ascii_case(raw_ext))
        .map(|(_, mime)| *mime)
}

/// Runs the real 3-request ActiveStorage direct-upload sequence (mirrored
/// from apps/earthenware/src/utils/fileUpload.ts) and returns the resulting
/// signed_id to reference in the create/update relationship payload.
/// Files above this are rejected before being read into memory - matches the
/// Attachments concern's own default 25MB cap (apps/kiln/app/models/concerns/
/// attachments.rb's DEFAULT_MAX_SIZE) with a small headroom margin, so this
/// actually catches an oversized file client-side before spending a full
/// upload round-trip on it, rather than a loose ceiling that would let a
/// 500MB file all the way to the server only to be rejected there. A few
/// specific attachments (e.g. Vendor#icon, Account#logo) override the server
/// default down to 5MB - this constant doesn't special-case those, so a file
/// between 25MB and this cap can still get a same server-side rejection for
/// those specific attachments; that's the server's authoritative limit to
/// enforce, not this client-side sanity check's job.
const MAX_UPLOAD_BYTES: u64 = 26 * 1024 * 1024;

/// Prints a hint before exiting when `prior_successes` (files already
/// uploaded to blob storage earlier in the same `--file` batch) is nonzero -
/// those blobs are now orphaned (uploaded but never attached to any
/// resource, since the whole create/update call is about to fail), so the
/// user needs to know that, not just that this one file failed.
fn warn_about_orphaned_prior_uploads(prior_successes: usize) {
    if prior_successes > 0 {
        let (files_word, was_word) = if prior_successes == 1 {
            ("file", "was")
        } else {
            ("files", "were")
        };
        eprintln!(
            "Note: {prior_successes} earlier {files_word} in this --file batch {was_word} already uploaded to blob storage but won't end up attached to anything, since this request will now fail."
        );
    }
}

/// Collapses the `eprintln!(...)` + `warn_about_orphaned_prior_uploads(...)` +
/// `std::process::exit(1)` triple repeated at every failure point in
/// `direct_upload`/`build_relationships` into one call - previously each of
/// those ~18 sites had to remember all three steps itself, with nothing
/// structurally enforcing that a future exit path added the orphan warning
/// before exiting.
fn fail(prior_successes: usize, message: impl std::fmt::Display) -> ! {
    eprintln!("{message}");
    warn_about_orphaned_prior_uploads(prior_successes);
    std::process::exit(1);
}

/// Defense-in-depth SSRF guard: the upload URL comes from the server's own
/// direct-upload response, so this only matters if Kiln itself is
/// compromised or misconfigured - but if it is, an unvalidated URL here
/// could point the CLI at an internal service or a cloud metadata endpoint
/// (e.g. `http://169.254.169.254/...`) with the file bytes as the request
/// body. Rejects a literal private/loopback/link-local/unspecified IP host.
/// This is *not* a complete mitigation: any non-numeric hostname passes
/// through entirely unchecked, whether it's a DNS-rebinding attack (resolves
/// differently at connect time than it would here) or simply a static
/// internal DNS alias that always points at a private IP (the common case
/// for cloud-internal metadata endpoints and private object-storage
/// deployments) - both require inspecting the resolved IP at the point
/// `raw_put` actually connects rather than at this URL-string level, a
/// materially larger change than this check.
///
/// Named for what it returns, not for an action it performs - it doesn't
/// reject anything itself, it returns `Some(reason)` when the caller should,
/// `None` when the URL looks safe to proceed with. The caller (`direct_upload`)
/// is the one that actually rejects.
///
/// Takes an already-parsed `Url` rather than parsing a `&str` itself -
/// `direct_upload` below already parses `upload_url` once to extract its
/// scheme, and by the time it reaches this check the scheme check has
/// already `fail()`-ed (which never returns) unless that parse succeeded, so
/// re-parsing the same string here would just repeat an always-successful
/// parse for no benefit.
fn private_network_rejection_reason_for_parsed_url(parsed: &url::Url) -> Option<&'static str> {
    let Some(host) = parsed.host_str() else {
        return Some("a URL with no host");
    };
    // Borrowed from `parsed` (still in scope for the rest of this function),
    // not `.to_string()`'d into an owned copy - `parsed` already owns the
    // data `host_str()` returns a `&str` into, so there's nothing to extend
    // the lifetime of here; the allocation would just be wasted on every
    // call.
    // Not redundant with `host_str()` - confirmed empirically (again, since
    // a prior review round claimed the opposite) that `host_str()` retains
    // the brackets on a bracketed IPv6 host (`"http://[::1]:3000"` parses to
    // `host_str() == Some("[::1]")`, not `Some("::1")`), so stripping them
    // here is required before `IpAddr::parse` (which rejects the bracketed
    // form) can succeed.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    // Strips a zone ID (e.g. the `%eth0` in `fe80::1%eth0`) before parsing.
    // In practice this is currently unreachable dead code, not a live
    // defense: confirmed empirically that `url::Url::parse` itself rejects
    // *every* zone-ID-qualified IPv6 host form outright ("invalid IPv6
    // address"), both the RFC 6874 `%25`-encoded form and the bare `%` form,
    // bracketed or not - so a URL carrying one never survives the `?` two
    // lines above to reach `host_str()` at all. Left in as harmless,
    // zero-cost defense-in-depth (a no-op via `.unwrap_or(host)` on the
    // common case with no `%`) in case a future `url` crate version parses
    // these where the current one doesn't.
    let host = host.split('%').next().unwrap_or(host);
    let ip: std::net::IpAddr = host.parse().ok()?;
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Some("a loopback address")
            } else if v4.is_private() {
                Some("a private (RFC 1918) address")
            } else if v4.is_link_local() {
                Some("a link-local address (this range includes cloud metadata endpoints)")
            } else if v4.is_unspecified() {
                Some("the unspecified address")
            } else {
                None
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("a loopback address")
            } else if v6.is_unspecified() {
                Some("the unspecified address")
            } else if v6.is_unicast_link_local() {
                // fe80::/10 - the IPv6 equivalent of the IPv4 link-local
                // range checked above, which is exactly where cloud
                // metadata endpoints (e.g. 169.254.169.254) live. Without
                // this arm, `http://[fe80::1]/...` sailed straight through.
                Some("a link-local address (this range includes cloud metadata endpoints)")
            } else if v6.is_unique_local() {
                // Unique local address range (fc00::/7) - `is_unique_local()`
                // has been stable since Rust 1.71, and rust-toolchain.toml
                // pins 1.88.0 here, so there's no need for the manual
                // bitmask this used to be.
                Some("a unique local (private) IPv6 address")
            } else {
                None
            }
        }
    }
}

pub(crate) fn direct_upload(
    client: &ApiClient,
    path: &Path,
    prior_successes: usize,
    force_insecure: bool,
) -> String {
    // Opens the file once and checks/reads through that same handle, rather
    // than a separate fs::metadata() + fs::read() pair - the latter has a
    // TOCTOU gap where the file could be swapped for a larger one between
    // the size check and the read, bypassing the size guard and reading an
    // unbounded amount into memory. Tying both operations to one descriptor,
    // plus the `is_file()` rejection just below, is what makes "the size
    // actually read is guaranteed to be the size checked" true.
    let file = fs::File::open(path).unwrap_or_else(|e| {
        fail(
            prior_successes,
            format_args!("Could not open {}: {e}", path.display()),
        )
    });
    let metadata = file.metadata().unwrap_or_else(|e| {
        fail(
            prior_successes,
            format_args!("Could not stat {}: {e}", path.display()),
        )
    });
    // Rejected before the length check below, not just relied on implicitly -
    // `st_size` (what `.len()` reads) is 0 for a FIFO, a `/proc` pseudo-file,
    // or most device nodes even when they have readable data, so without
    // this check those inputs would trivially pass the length guard below
    // and `take(MAX_UPLOAD_BYTES + 1).read_to_end` would still buffer up to
    // that many bytes before the post-read check caught it, rather than
    // being rejected up front.
    if !metadata.is_file() {
        fail(
            prior_successes,
            format_args!(
                "{} is not a regular file - refusing to upload it.",
                path.display()
            ),
        );
    }
    let file_len = metadata.len();
    if file_len > MAX_UPLOAD_BYTES {
        fail(
            prior_successes,
            format_args!(
                "{} is too large to upload ({file_len} bytes; limit is {MAX_UPLOAD_BYTES} bytes)",
                path.display()
            ),
        );
    }
    // `Vec::with_capacity` only preallocates - it doesn't cap what
    // `read_to_end` will actually consume. For a plain regular file that's
    // moot (its length is fixed at open time), but a FIFO, a `/proc`
    // pseudo-file, or a file that grows after this `open()` call could all
    // read past MAX_UPLOAD_BYTES, silently defeating the size guard above.
    // `Read::take` bounds the read itself, and reading one extra byte
    // (`MAX_UPLOAD_BYTES + 1`) lets the length check below distinguish
    // "exactly at the limit" from "the source kept growing past it".
    let mut bytes = Vec::with_capacity(file_len.min(MAX_UPLOAD_BYTES + 1) as usize);
    file.take(MAX_UPLOAD_BYTES + 1)
        .read_to_end(&mut bytes)
        .unwrap_or_else(|e| {
            fail(
                prior_successes,
                format_args!("Could not read {}: {e}", path.display()),
            )
        });
    if bytes.len() as u64 > MAX_UPLOAD_BYTES {
        fail(
            prior_successes,
            format_args!(
                "{} is too large to upload (limit is {MAX_UPLOAD_BYTES} bytes)",
                path.display()
            ),
        );
    }
    // `to_string_lossy()` (replacing non-UTF-8 bytes with U+FFFD), not a
    // blanket `"upload"` fallback - ActiveStorage uses this exact filename
    // for both content-type detection and the `Content-Disposition` header
    // it generates on download, so a non-UTF-8 filename falling back to the
    // literal string "upload" would have every later download of this file
    // served back under that name, with its real extension (and therefore a
    // real chance at correct content-type sniffing) discarded entirely. The
    // lossy conversion still looks like the real filename to a human and
    // keeps the extension.
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "upload".to_string());
    let content_type = content_type_for(path).unwrap_or_else(|| {
        // Distinguishes three cases, not two - `path.extension()` (raw
        // `Option<&OsStr>`) is checked before ever calling `.to_str()`, so a
        // genuinely extension-less file (Makefile, LICENSE, Dockerfile) is
        // never conflated with one whose extension exists but isn't valid
        // UTF-8. An earlier version called `.and_then(|e| e.to_str())`
        // directly, which collapsed both into the same `None` arm and always
        // printed "has no file extension" even when a (non-UTF-8) extension
        // was actually present. The non-UTF-8 case uses `to_string_lossy()`
        // purely for display here - unlike `content_type_for`'s own lookup,
        // which correctly treats it as "doesn't match the allow-list"
        // regardless, this branch only needs *something* readable to show
        // the user, not a byte-accurate round-trip.
        let message = match path.extension() {
            Some(ext) => match ext.to_str() {
                Some(ext) => format!(
                    "{} has an unrecognized file extension (.{ext}) - Kiln only accepts a specific allow-list of file types (images, PDF, JSON/XML/ZIP, the Office spreadsheet type, plain text/CSV/Markdown).",
                    path.display()
                ),
                None => format!(
                    "{} has a file extension with non-UTF-8 bytes (.{}) - Kiln only accepts a specific allow-list of file types (images, PDF, JSON/XML/ZIP, the Office spreadsheet type, plain text/CSV/Markdown).",
                    path.display(),
                    ext.to_string_lossy()
                ),
            },
            // A dotfile (`.env`, `.gitignore`, `.pem`) also lands here -
            // `Path::extension()` treats the entire name after a leading `.`
            // as the stem, not an extension, for a name with no other `.` in
            // it. Called out with its own message rather than the generic
            // "has no file extension" one below: that wording reads as if
            // the file just happens to lack an extension, which is
            // confusing for a file whose name the user very deliberately
            // started with `.`.
            // `n.get(1..)`, not `n[1..]` - the latter is safe today only
            // because `starts_with('.')` guarantees byte 0 is the single-byte
            // ASCII `.`, but that's an implicit invariant a future edit could
            // break (reordering the checks, or copying this condition
            // somewhere byte 0 isn't guaranteed ASCII) and turn into a
            // runtime panic. `.get(1..)` can't panic regardless.
            None if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.') && !n.get(1..).is_some_and(|tail| tail.contains('.'))) =>
            {
                format!(
                    "{} is a dotfile with no extension (Rust's Path::extension() treats the whole name as the stem here) - Kiln only accepts a specific allow-list of file types (images, PDF, JSON/XML/ZIP, the Office spreadsheet type, plain text/CSV/Markdown).",
                    path.display()
                )
            }
            None => format!(
                "{} has no file extension - Kiln only accepts a specific allow-list of file types (images, PDF, JSON/XML/ZIP, the Office spreadsheet type, plain text/CSV/Markdown).",
                path.display()
            ),
        };
        fail(prior_successes, message)
    });
    // Safe: MAX_UPLOAD_BYTES (26MB) is well under i64::MAX (the
    // ActiveStorage `byte_size` column is a PostgreSQL bigint / signed
    // 64-bit integer). The stat check above bounds bytes.len() to that same
    // ceiling.
    let byte_size = bytes.len() as i64;

    let mut hasher = Md5::new();
    hasher.update(&bytes);
    let checksum = STANDARD.encode(hasher.finalize());

    let blob_request = json!({
        "blob": {
            "filename": filename,
            "byte_size": byte_size,
            "checksum": checksum,
            "content_type": content_type,
        }
    });
    // `unwrap_or_else` + `process::exit`, not `.expect()` - a panic here
    // would unwind straight through `build_relationships`' loop without
    // printing `warn_about_orphaned_prior_uploads`, breaking that function's
    // documented invariant that `direct_upload` never returns without
    // either succeeding or having already reported any earlier orphaned
    // uploads in the batch. `panic = "abort"` isn't set in Cargo.toml, so
    // the default unwind would otherwise skip that reporting silently.
    let request_bytes = serde_json::to_vec(&blob_request).unwrap_or_else(|e| {
        fail(
            prior_successes,
            format_args!("Failed to serialize blob request: {e}"),
        )
    });

    let response = client.raw_post(
        &format!(
            "{}/rails/active_storage/direct_uploads",
            client.base_url_trimmed()
        ),
        &[("Content-Type", "application/json")],
        &request_bytes,
    );
    let status = response.status;
    // `is_success()` (which also accounts for an unparseable 2xx body), not
    // a raw status-range check - the latter would fall through to `body.
    // get("signed_id")` on a `Value::Null` placeholder for a 2xx response
    // whose body failed to parse, producing the misleading "missing
    // signed_id" message below instead of a message about the real problem.
    if !response.is_success() {
        fail(
            prior_successes,
            format_args!(
                "Direct upload setup failed ({status}): {}",
                response.error_detail()
            ),
        );
    }
    let body = response.body().unwrap_or_else(|| {
        fail(
            prior_successes,
            format_args!(
                "Direct upload setup succeeded ({status}) but returned no usable JSON body."
            ),
        )
    });

    let signed_id = body
        .get("signed_id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| fail(prior_successes, "Direct upload response missing signed_id"))
        .to_string();

    let direct_upload_obj = body.get("direct_upload").unwrap_or_else(|| {
        fail(
            prior_successes,
            "Direct upload response missing direct_upload object",
        )
    });
    let upload_url = direct_upload_obj
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            fail(
                prior_successes,
                "Direct upload response missing direct_upload.url",
            )
        })
        .to_string();
    // Scheme extracted via `url::Url::parse` (which normalizes it to
    // lowercase), not a case-sensitive `starts_with("http://")` string
    // check - a server returning a mixed-case scheme (`HTTP://...`,
    // `Http://...`) would otherwise fail *both* the `http://` and `https://`
    // checks below and land in the generic "non-http(s)" rejection instead
    // of the TLS-specific one, and - more importantly - would bypass the
    // `force_insecure` gate entirely if this logic were ever restructured,
    // silently uploading file bytes in plaintext with neither the warning
    // nor the error this check exists to produce.
    let parsed_upload_url = url::Url::parse(&upload_url);
    let upload_scheme = parsed_upload_url
        .as_ref()
        .ok()
        .map(|u| u.scheme().to_string());
    if upload_scheme.as_deref() == Some("http") {
        // Same standard as config.rs's `enforce_secure` for the API base
        // URL itself: a hard error by default (file bytes - potentially
        // SOC2 reports, security questionnaires, privacy policies - would
        // otherwise go out in plaintext with only a warning, which a script
        // could easily never surface to a human), downgradeable to a
        // warning via the same `--force-insecure`/`KLAAY_ALLOW_INSECURE`
        // opt-in rather than a second, separately-named flag for what's the
        // same underlying decision. Not rejected outright regardless of the
        // flag - a genuinely `http://`-only object storage endpoint isn't
        // impossible in a self-hosted setup.
        if force_insecure {
            eprintln!(
                "Warning: direct upload URL is non-TLS (http://); file bytes will be transmitted in plaintext."
            );
        } else {
            fail(
                prior_successes,
                "Error: direct upload URL is non-TLS (http://) - file bytes would be transmitted in plaintext.\nPass --force-insecure or set KLAAY_ALLOW_INSECURE=1 (or =true / =yes) if this is intentional.",
            );
        }
    } else if upload_scheme.as_deref() != Some("https") {
        fail(
            prior_successes,
            format_args!("Direct upload response returned a non-http(s) upload URL: {upload_url}"),
        );
    }
    // `.expect()`, not a fallible path - the scheme check above already
    // `fail()`-ed (which never returns) unless `parsed_upload_url` parsed
    // successfully, so by this point it's always `Ok`.
    let parsed_upload_url_ref = parsed_upload_url
        .as_ref()
        .expect("scheme check above already rejected an unparseable URL");
    if let Some(reason) = private_network_rejection_reason_for_parsed_url(parsed_upload_url_ref) {
        fail(
            prior_successes,
            format_args!(
                "Direct upload response returned a URL pointing at {reason}, refusing to upload to it: {upload_url}"
            ),
        );
    }

    // Only forward headers the blob-storage PUT actually needs - the response
    // is server-controlled (our own Kiln backend), but there's no reason to
    // blindly relay an arbitrary header set onto an outbound request.
    // Content-Length is deliberately not in this list - it must always be
    // derived from the actual body bytes passed to raw_put (ureq sets it
    // correctly on its own), never relayed from the server's response. A
    // server-supplied value that doesn't match the real byte count would
    // either truncate the upload or send a request whose declared length
    // disagrees with what's actually on the wire.
    // Lowercase literals, matched below via plain `==` against `k_lower`
    // (already lowercased) - avoids case-folding one already-canonical side
    // of the comparison on every iteration, and reads as a direct membership
    // check rather than obscuring that both sides are already known-case.
    // Actual outgoing header names still use the server's original casing
    // (`k.clone()` below, not these literals) - this list only ever gates
    // membership, never gets sent over the wire itself.
    const ALLOWED_UPLOAD_HEADERS: &[&str] = &[
        "content-type",
        "content-md5",
        "content-disposition",
        "x-amz-checksum-crc32",
        // CRC32C, not just plain CRC32 - some S3 bucket configurations/SDK
        // versions use this variant as the checksum header on direct PUT
        // uploads instead. Without both listed, whichever one Kiln's
        // ActiveStorage/S3 configuration actually returns would be silently
        // filtered out here (it matches neither the exact-name list nor a
        // prefix rule below), and the PUT would fail with a confusing S3
        // checksum-policy/signature error rather than a clear diagnostic.
        "x-amz-checksum-crc32c",
        // The separate trailing-checksum header for payload integrity - not
        // the same thing as `x-amz-content-sha256` below (that one is the
        // content hash used in the canonical request/signature). Buckets
        // configured with `x-amz-sdk-checksum-algorithm: SHA256` (or that
        // otherwise enforce a checksum policy) require this on the PUT;
        // without it in the allow-list it would be silently dropped here,
        // and the PUT would fail with a confusing S3 signature/auth error
        // instead of a clear diagnostic.
        "x-amz-checksum-sha256",
        "x-amz-content-sha256",
        "x-amz-sdk-checksum-algorithm",
    ];
    // Prefix-matched separately from the exact-name list above - this list
    // was only validated against S3, and Kiln's ActiveStorage backend could
    // just as well be configured for Google Cloud Storage or Azure Blob
    // Storage, whose required PUT headers (`x-goog-*`, `x-ms-*`) aren't
    // known ahead of time as exact names. Without this, those headers would
    // be silently dropped here, and the PUT would fail with a confusing
    // auth error from the blob-storage provider rather than from Kiln.
    //
    // Deliberately the whole namespace prefix, not an exact enumeration
    // (e.g. Azure's actual PUT-blob requirements are commonly cited as
    // `x-ms-blob-type`/`x-ms-date`/`x-ms-version`/`x-ms-blob-content-type`)
    // - unlike the S3 exact-name list above, which this project directly
    // verified, no Azure deployment has been exercised against this code to
    // confirm which exact headers ActiveStorage's Azure adapter actually
    // sends, so enumerating a guessed list here risks silently breaking a
    // real Azure upload if the guess is wrong or incomplete. The trade-off
    // accepted instead: if Kiln's own backend response ever included an
    // unintended `x-ms-*`/`x-goog-*` header, it would be forwarded here
    // unfiltered - acceptable since `direct_upload.headers` is the
    // server's own response, not attacker input, on a request this CLI
    // itself just initiated.
    const ALLOWED_UPLOAD_HEADER_PREFIXES: &[&str] = &["x-goog-", "x-ms-"];
    // Collected directly into the Vec pairs raw_put wants - going through an
    // intermediate HashMap first (as an earlier version did) only to
    // immediately re-collect it into this same shape was an unnecessary
    // allocation with no benefit, since nothing here needs key lookups.
    //
    // Distinguishes "headers" being absent entirely (the server intentionally
    // sent no headers - fine, proceeds with an empty Vec silently) from being
    // present but not an object (a malformed response) - collapsing both into
    // the same `.unwrap_or_default()` would silently proceed with zero
    // headers either way, and if the blob storage provider requires
    // authentication headers in the PUT, that failure would surface only as
    // an opaque auth error from the provider with no client-side indication
    // that header forwarding itself was ever skipped.
    let header_pairs: Vec<(String, String)> = match direct_upload_obj.get("headers") {
        None => Vec::new(),
        Some(headers_value) => match headers_value.as_object() {
            // Single `.filter_map()`, not a `.filter()` followed by a
            // separate `.filter_map()` - the two-step version computed
            // `k_lower` in the filter and then paid a separate `k.clone()`
            // in the filter_map for every entry that passed, two heap
            // allocations per kept header. Computing `k_lower` once here and
            // reusing it for the allow-check means an entry that fails the
            // allowlist gate costs one allocation (the lowercase check
            // itself), not two.
            Some(obj) => obj
                .iter()
                .filter_map(|(k, v)| {
                    let k_lower = k.to_ascii_lowercase();
                    let allowed = ALLOWED_UPLOAD_HEADERS.iter().any(|a| *a == k_lower)
                        || ALLOWED_UPLOAD_HEADER_PREFIXES
                            .iter()
                            .any(|prefix| k_lower.starts_with(prefix));
                    if !allowed {
                        return None;
                    }
                    v.as_str().map(|s| (k.clone(), s.to_string())).or_else(|| {
                        eprintln!(
                            "Warning: direct upload header '{k}' has a non-string value ({}), skipping - the blob PUT may fail.",
                            json_type_name(v)
                        );
                        None
                    })
                })
                .collect(),
            None => {
                eprintln!(
                    "Warning: direct upload response has a non-object 'headers' field ({}) - proceeding without forwarding headers, the blob PUT may fail.",
                    json_type_name(headers_value)
                );
                Vec::new()
            }
        },
    };

    // stderr, not stdout - every command's actual data output goes to stdout
    // (see main.rs), so a progress message mixed into it would corrupt
    // anything piping/parsing that output (e.g. `klaay create ... | jq`).
    // `path.display()`, not `filename` - every other user-facing message in
    // this function already uses `path.display()`, which lossily decodes the
    // actual path rather than silently falling back to the generic literal
    // "upload" the way `filename` (used below for the server-sent blob
    // metadata, where a real string is required) does for a non-UTF-8
    // filename. Using `filename` here would tell the user "Uploading
    // upload... done" with no indication of which file was actually
    // processed.
    eprintln!("Uploading {}...", path.display());
    // Passed directly - `raw_put` takes `&[(String, String)]`, so there's no
    // need to first collect a second, borrowed-`&str` `Vec` just to satisfy
    // its signature.
    let put_response = client.raw_put(&upload_url, &header_pairs, &bytes);
    if !put_response.is_success() {
        // Includes the response body, matching the blob-creation failure
        // above - blob-storage providers (S3, GCS, Azure) return a detailed
        // XML/JSON error body explaining the real cause (a signature
        // mismatch, a checksum policy violation, a bucket ACL problem), and
        // the status code alone gives no way to diagnose which.
        fail(
            prior_successes,
            format_args!(
                "File upload to blob storage failed with status {}: {}",
                put_response.status,
                put_response.error_detail()
            ),
        );
    }
    eprintln!("Uploading {}... done", path.display());

    signed_id
}

/// Every `has_one_attached` relationship name across the app (confirmed
/// directly via grep of every model, not guessed) - JSON:API expects a
/// single object in `data` for these, not the has-many array this function
/// builds for everything else. Rather than silently sending a malformed
/// `"data": [...]` the server would reject anyway, a `--file` targeting one
/// of these exits with a clear message up front.
///
/// No mechanism keeps this in sync with the server if a new
/// `has_one_attached` is added there later - a missing entry would silently
/// send the malformed array shape (rejected only after the file has already
/// been uploaded to blob storage, orphaning it). When adding a new
/// attachment, check these model files directly rather than assuming this
/// list is exhaustive:
/// - `app/models/account.rb` (`logo`)
/// - `app/models/user_import.rb` (`source`)
/// - `app/models/predefined_vendor.rb` (`icon`)
/// - `app/models/evidence_run_export.rb` (`export`)
/// - `app/models/vendor.rb` (`icon`, `data_agreement`, `soc2_report`,
///   `iso27001_report`, `security_questionnaire`, `privacy_policy_document`,
///   `terms_of_use_document`)
///
/// Verified complete as of this writing via `grep -rl has_one_attached
/// app/models/` (five model files above, plus the `has_one_attached` method
/// definition itself inside `app/models/concerns/attachments.rb` - not a
/// real attachment). Models with attachment-like names that are deliberately
/// absent because they use `has_many_attached` instead (a real has-many
/// array is correct for these, not a bug in this list):
/// `account_user.rb`, `calendar_occurrence.rb`, `collected_evidence.rb`,
/// `evidence_check.rb`, `message.rb`, `task.rb`.
const KNOWN_HAS_ONE_RELATIONSHIPS: &[&str] = &[
    "logo",
    "source",
    "icon",
    "export",
    "data_agreement",
    "soc2_report",
    "iso27001_report",
    "security_questionnaire",
    "privacy_policy_document",
    "terms_of_use_document",
];

/// Parses a repeatable `--file <relationship>=<path>` flag and merges the
/// resulting active_storage_blobs relationship(s) into a JSON:API relationships
/// object. Multiple files for the same relationship key become a has-many
/// array; a single file also uses array form, matching every attachment this
/// plan verified directly (CollectedEvidence#files, Vendor#documents, etc. are
/// all has_many_attached) - a true has_one target is rejected explicitly
/// above rather than sent as a malformed array.
pub(crate) fn build_relationships(
    client: &ApiClient,
    file_flags: &[(String, String)],
    force_insecure: bool,
) -> Value {
    // BTreeMap (not HashMap) - HashMap's iteration order is randomized per
    // process, so the same --file flags could serialize their relationships
    // in a different order run to run. JSON:API servers don't care about key
    // order, but a stable order still matters for anything that diffs or
    // snapshots the serialized request (logs, tests, tooling).
    let mut grouped: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    // Counted explicitly rather than relied upon via the loop's own index -
    // `direct_upload` never returns on failure (it always
    // `std::process::exit(1)`s), so today this always equals the loop index
    // at each point anyway, but incrementing it only after a real success
    // means this stays correct even if `direct_upload` is ever changed to
    // return a `Result` instead of exiting - no implicit invariant for a
    // future change to silently break.
    let mut successes = 0usize;
    // clippy's explicit_counter_loop suggests `.enumerate()` here, but that's
    // exactly the coupling this counter exists to avoid - see the comment
    // above. `successes` is incremented after `direct_upload` returns, not
    // derived from the loop position, even though the two happen to match
    // today.
    #[expect(
        clippy::explicit_counter_loop,
        reason = "successes must only increment after a confirmed direct_upload return, not at the loop index boundary"
    )]
    for (relationship, path_str) in file_flags {
        // A plain slice scan, not a `HashSet` built once outside this loop -
        // a prior version of this code built the set specifically to make
        // lookups here "O(1)", but `KNOWN_HAS_ONE_RELATIONSHIPS` is a fixed
        // 10-entry compile-time constant, so scanning it is already O(1) in
        // the only variable that matters here (the number of `--file` flags,
        // m): the two approaches are the same O(m) asymptotic class either
        // way, since building a HashSet from those same 10 entries is itself
        // O(1). A `HashSet`'s allocation would be pure overhead for no
        // asymptotic benefit, not a tradeoff against a bigger-O scan.
        if KNOWN_HAS_ONE_RELATIONSHIPS.contains(&relationship.as_str()) {
            fail(
                successes,
                format_args!(
                    "Error: \"{relationship}\" is a single-file (has_one) attachment - it needs a single object, not the array this generic --file path builds. Not yet supported; ask for it if you need it."
                ),
            );
        }
        let path = Path::new(path_str);
        let signed_id = direct_upload(client, path, successes, force_insecure);
        successes += 1;
        grouped
            .entry(relationship.clone())
            .or_default()
            .push(json!({
                "type": "active_storage_blobs",
                "id": signed_id,
            }));
    }

    let mut relationships = serde_json::Map::new();
    for (relationship, refs) in grouped {
        relationships.insert(relationship, json!({ "data": refs }));
    }
    Value::Object(relationships)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_for_recognizes_known_extensions() {
        assert_eq!(content_type_for(Path::new("photo.png")), Some("image/png"));
        assert_eq!(
            content_type_for(Path::new("report.PDF")),
            Some("application/pdf")
        );
        assert_eq!(
            content_type_for(Path::new("data.XLS")),
            Some("application/vnd.ms-excel")
        );
    }

    #[test]
    fn content_type_for_returns_none_for_unrecognized_extension() {
        assert_eq!(content_type_for(Path::new("file.xyz")), None);
    }

    #[test]
    fn content_type_for_returns_none_for_no_extension() {
        assert_eq!(content_type_for(Path::new("Makefile")), None);
    }

    #[test]
    fn content_type_for_returns_none_for_dotfile_with_no_inner_dot() {
        assert_eq!(content_type_for(Path::new(".env")), None);
    }

    #[test]
    fn content_type_for_treats_dotfile_with_inner_dot_as_an_extension() {
        // `Path::extension()` treats everything after the last dot as the
        // extension once there's more than one dot in the filename - ".bak"
        // here, which isn't in the recognized table, so this falls through
        // to the same "unrecognized extension" `None` as `file.xyz` above,
        // not to the "no extension at all" `None` `.env` gets.
        assert_eq!(content_type_for(Path::new(".env.bak")), None);
    }

    fn parsed(url: &str) -> url::Url {
        url::Url::parse(url).expect("test URL literal should always parse")
    }

    #[test]
    fn private_network_rejection_reason_rejects_ipv4_loopback() {
        assert!(private_network_rejection_reason_for_parsed_url(&parsed(
            "https://127.0.0.1/direct_upload"
        ))
        .is_some());
    }

    #[test]
    fn private_network_rejection_reason_rejects_ipv4_private_range() {
        assert!(private_network_rejection_reason_for_parsed_url(&parsed(
            "https://10.0.0.1/direct_upload"
        ))
        .is_some());
        assert!(private_network_rejection_reason_for_parsed_url(&parsed(
            "https://192.168.1.1/direct_upload"
        ))
        .is_some());
    }

    #[test]
    fn private_network_rejection_reason_rejects_ipv4_link_local() {
        assert!(private_network_rejection_reason_for_parsed_url(&parsed(
            "https://169.254.169.254/latest"
        ))
        .is_some());
    }

    #[test]
    fn private_network_rejection_reason_rejects_bracketed_ipv6_loopback() {
        assert!(private_network_rejection_reason_for_parsed_url(&parsed(
            "https://[::1]/direct_upload"
        ))
        .is_some());
    }

    #[test]
    fn private_network_rejection_reason_rejects_ipv6_link_local() {
        assert!(private_network_rejection_reason_for_parsed_url(&parsed(
            "https://[fe80::1]/direct_upload"
        ))
        .is_some());
    }

    #[test]
    fn private_network_rejection_reason_rejects_ipv6_unique_local() {
        assert!(private_network_rejection_reason_for_parsed_url(&parsed(
            "https://[fc00::1]/direct_upload"
        ))
        .is_some());
    }

    #[test]
    fn private_network_rejection_reason_allows_public_hostname() {
        assert_eq!(
            private_network_rejection_reason_for_parsed_url(&parsed(
                "https://blob-storage.example.com/direct_upload"
            )),
            None
        );
    }

    #[test]
    fn private_network_rejection_reason_allows_public_ipv4() {
        assert_eq!(
            private_network_rejection_reason_for_parsed_url(&parsed(
                "https://8.8.8.8/direct_upload"
            )),
            None
        );
    }
}
