// SPDX-License-Identifier: GPL-3.0-or-later
use serde_json::Value;
use std::collections::HashMap;

pub(crate) struct ApiClient {
    agent: ureq::Agent,
    base_url: String,
    // Full `"Bearer <token>"` header, validated and built once in `new()`
    // instead of per-request. Zeroized on drop like every other bearer
    // credential here. Private so no caller can clone an unzeroized copy or
    // `take()` the value out past this struct's Drop - `bearer()` is the only
    // sanctioned reader.
    auth_header: Option<zeroize::Zeroizing<String>>,
}

/// How `send()` classified the response body - one value instead of the two
/// coupled booleans it replaced, so the nonsensical "parse-failed yet parsed"
/// combination can't be represented and `error_detail()` is a flat match.
#[derive(Debug)]
enum BodyKind {
    /// Valid JSON - a normal success or a JSON:API error body.
    Json,
    /// No body at all (e.g. a 204). Distinct from a genuine JSON `null`.
    Empty,
    /// Body wasn't JSON; `send()` already previewed it in a warning.
    ParseFailed,
    /// A 404 with a non-JSON `text/html` body - an unrouted path, so
    /// `error_detail()` gives a "resource name is probably wrong" hint. Only set
    /// on the non-empty parse-failure arm, where the preview always prints, so
    /// the hint's reference to that warning is always accurate.
    UnroutedHtml404,
}

// No `#[derive(Debug)]`: `body` can hold sensitive server data (PII, error
// messages echoing input), and `{:?}` would dump it. `BodyKind` derives Debug
// for internal diagnostics; add a redacting manual impl here if one is needed.
pub(crate) struct ApiResponse {
    pub(crate) status: u16,
    // Private: reading it directly risks mistaking a parse-failure placeholder
    // (`Value::Null`) for a genuine server `null` without first checking
    // `is_success()`. Use `body()`/`raw_body()`/`into_raw_body()`.
    body: Value,
    kind: BodyKind,
}

/// HTTP methods `klaay call` supports. No `clap` derive here to keep this HTTP
/// layer decoupled from CLI argument parsing; `main.rs` wraps it with a
/// `ValueEnum` type that converts via `From`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum HttpMethod {
    Get,
    Post,
    Patch,
    Put,
    Delete,
}

impl HttpMethod {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// The 3 HTTP methods `write()` implements. A local enum (vs the
/// non-exhaustive `ureq::http::Method`) makes the match exhaustive at compile
/// time instead of needing a runtime catch-all arm.
enum WriteMethod {
    Post,
    Patch,
    Put,
}

impl ApiResponse {
    pub(crate) fn is_success(&self) -> bool {
        // An empty 2xx (e.g. 204 No Content) is a success with no body.
        (200..300).contains(&self.status) && matches!(self.kind, BodyKind::Json | BodyKind::Empty)
    }

    /// The parsed body, or `None` if the response had no body or one that wasn't
    /// valid JSON (distinct from a genuine `null`). Check `is_success()` before
    /// treating it as real data. `None` covers three cases - an empty body, a
    /// parse failure, and an unrouted HTML 404 - which a caller can't tell apart
    /// from this alone, so the `body().unwrap_or_else` sites word their message
    /// to cover them all.
    pub(crate) fn body(&self) -> Option<&Value> {
        match self.kind {
            BodyKind::Json => Some(&self.body),
            BodyKind::Empty | BodyKind::ParseFailed | BodyKind::UnroutedHtml404 => None,
        }
    }

    /// The body regardless of parse success - `Value::Null` on failure. For
    /// diagnostic/error-display call sites past their own `is_success()` check.
    pub(crate) fn raw_body(&self) -> &Value {
        &self.body
    }

    /// Consuming counterpart of `raw_body()`, for call sites that need to move
    /// the body out rather than borrow it.
    pub(crate) fn into_raw_body(self) -> Value {
        self.body
    }

    /// Human-readable body for error display. Distinguishes an empty response
    /// from a non-JSON body (whose real content `send()` already previewed) so
    /// the latter doesn't render as the bare, misleading string `"null"`.
    pub(crate) fn error_detail(&self) -> String {
        match self.kind {
            BodyKind::UnroutedHtml404 => format!(
                "This path returned an HTML 404, not a JSON:API response. If you were addressing a resource, its name may be wrong - run `{bin} resources` to see valid ones. Otherwise an upstream proxy or CDN likely returned an HTML page (its body is previewed on stderr).",
                bin = crate::config::bin_name()
            ),
            BodyKind::ParseFailed => {
                "(response body was not valid JSON - see warning above)".to_string()
            }
            BodyKind::Empty => "(no response body)".to_string(),
            BodyKind::Json => serde_json::to_string(&self.body).unwrap_or_default(),
        }
    }
}

#[derive(Default)]
pub(crate) struct ListParams {
    pub(crate) filters: Vec<(String, String)>,
    pub(crate) sort: Option<String>,
    pub(crate) include: Option<String>,
    pub(crate) fields: Option<(String, String)>,
    pub(crate) page_number: Option<u32>,
    pub(crate) page_size: Option<u32>,
}

impl ApiClient {
    pub(crate) fn new(base_url: String, token: Option<zeroize::Zeroizing<String>>) -> Self {
        // http_status_as_error(false): non-2xx bodies still parse as JSON:API
        // errors rather than opaque ureq::Errors. Timeouts bound how long a
        // hung server can block the process.
        // Names this client and its version on every request. Without it the
        // server cannot tell a CLI call from anything else, so the count that
        // decides when an old endpoint may be removed has nobody to name.
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(concat!("klaay-cli/", env!("CARGO_PKG_VERSION")))
            .timeout_connect(Some(std::time::Duration::from_secs(10)))
            .timeout_global(Some(std::time::Duration::from_secs(60)))
            .build();
        ApiClient {
            agent: ureq::Agent::new_with_config(config),
            base_url,
            auth_header: token.map(Self::build_auth_header),
        }
    }

    /// Validates and formats the `"Bearer <token>"` header once (see the
    /// `auth_header` field). Exits the process rather than downgrading to an
    /// unauthenticated request if `token` contains non-JWT characters, since
    /// callers treat a `None` header as "just don't attach auth". Takes `t` by
    /// value so the invalid-input exit path can zero the real buffer.
    fn build_auth_header(mut t: zeroize::Zeroizing<String>) -> zeroize::Zeroizing<String> {
        // An empty token passes the `chars().all(...)` charset check vacuously
        // and would build a bare `"Bearer "` header. `require_login` rejects it
        // upstream, but `new()` is `pub(crate)`, so guard at the boundary.
        if t.is_empty() {
            eprintln!(
                "Stored token is empty - run `{} login` again.",
                crate::config::bin_name()
            );
            // `process::exit` skips stack unwinding, so `Zeroizing`'s Drop
            // won't run - zeroize explicitly (same as the charset branch below).
            zeroize::Zeroize::zeroize(&mut *t);
            std::process::exit(1);
        }
        // JWT charset only (base64url + `-`/`_`/`.`) - matches
        // `auth::require_login`. `is_ascii_graphic()` would let JWT-illegal
        // chars like `"`, `#`, `\` reach ureq's header API verbatim.
        if !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            eprintln!(
                "Stored token contains invalid characters - run `{} login` again.",
                crate::config::bin_name()
            );
            zeroize::Zeroize::zeroize(&mut *t);
            std::process::exit(1);
        }
        // Build directly in the Zeroizing buffer, not via `Zeroizing::new(
        // format!(...))`: `format!` would first allocate an unprotected
        // `String` the later wrap can't retroactively zero (same reason as
        // `auth.rs`'s `build_secret_auth_body`).
        let mut header = zeroize::Zeroizing::new(String::with_capacity("Bearer ".len() + t.len()));
        header.push_str("Bearer ");
        header.push_str(t.as_str());
        header
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url_trimmed(), path)
    }

    /// Whitelist (alphanumerics, `-`, `_`) for path segments concatenated into
    /// the URL. A resource type or id never needs any other character, and a
    /// whitelist closes `?`/`#`/`%2F`/null-byte injection at once rather than
    /// blocklisting characters one by one.
    pub(crate) fn validate_path_segment(value: &str, name: &str) {
        // Explicit: `.chars().all(...)` is vacuously true over zero chars, so
        // an empty value would otherwise pass and produce `/resource/` or `//`.
        if value.is_empty() {
            eprintln!("Error: {name} must not be empty.");
            std::process::exit(1);
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            eprintln!(
                "Error: invalid {name} {value:?} - must contain only ASCII alphanumerics, hyphens, and underscores."
            );
            std::process::exit(1);
        }
    }

    /// Whitelist for `sort`/`include` query values - like
    /// `validate_path_segment` but also allowing `,` (multiple fields), `.`
    /// (nested relationships), and `-` (the descending-sort prefix, e.g.
    /// `--sort -name`). ureq percent-encodes these anyway, but the adjacent
    /// filter/fields values get an explicit whitelist too.
    fn validate_query_value(value: &str, name: &str) {
        if value.is_empty() {
            eprintln!("Error: {name} must not be empty.");
            std::process::exit(1);
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ','))
        {
            eprintln!(
                "Error: invalid {name} {value:?} - must contain only ASCII alphanumerics, hyphens, underscores, dots, and commas."
            );
            std::process::exit(1);
        }
    }

    /// Borrows the precomputed `auth_header` (validated once in `new()`).
    fn bearer(&self) -> Option<&zeroize::Zeroizing<String>> {
        self.auth_header.as_ref()
    }

    /// Attaches the bearer header if present. Centralizing this means a future
    /// request builder that skips it is visibly missing auth rather than
    /// silently omitting a copy-pasted `if let`. Generic over `ureq`'s
    /// `WithBody`/`WithoutBody` builder states.
    fn attach_auth<B>(&self, req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        if let Some(auth) = self.bearer() {
            req.header("Authorization", auth.as_str())
        } else {
            req
        }
    }

    /// Normalized base URL (trailing slash trimmed) for callers outside this
    /// module that build their own URL - e.g. upload.rs's ActiveStorage
    /// direct-upload endpoint.
    pub(crate) fn base_url_trimmed(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// GET a collection with JSON:API filter/sort/include/fields/page encoding.
    /// A filter key repeated across multiple `--filter` flags serializes as
    /// `filter[key][]=value` (a real array), since Kiln's scopes match nothing
    /// against a comma-joined string.
    pub(crate) fn list(&self, resource: &str, params: &ListParams) -> ApiResponse {
        Self::validate_path_segment(resource, "resource");
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (k, _) in &params.filters {
            *counts.entry(k.as_str()).or_insert(0) += 1;
        }

        let url = self.url(&format!("/{resource}"));
        let mut req = self.agent.get(&url);
        req = self.attach_auth(req);

        for (k, v) in &params.filters {
            // Same charset check as `resource` - filter scope names are always
            // valid Ruby identifiers. ureq percent-encodes the whole
            // `filter[...]` string anyway, but don't rest on that alone.
            Self::validate_path_segment(k, "filter key");
            // `.get()` not indexing - the count loop above guarantees the key
            // is present, but a miss yields "singular" formatting, not a panic.
            let key = if counts.get(k.as_str()).copied().unwrap_or(0) > 1 {
                format!("filter[{k}][]")
            } else {
                format!("filter[{k}]")
            };
            req = req.query(&key, v);
        }
        if let Some(sort) = &params.sort {
            Self::validate_query_value(sort, "sort");
            req = req.query("sort", sort);
        }
        if let Some(include) = &params.include {
            Self::validate_query_value(include, "include");
            req = req.query("include", include);
        }
        if let Some((type_, fields)) = &params.fields {
            // Same charset guard as filter keys - `type_` is interpolated into
            // the query key.
            Self::validate_path_segment(type_, "fields type");
            req = req.query(format!("fields[{type_}]"), fields);
        }
        if let Some(n) = params.page_number {
            req = req.query("page[number]", n.to_string());
        }
        if let Some(n) = params.page_size {
            req = req.query("page[size]", n.to_string());
        }

        send(req.call(), &url)
    }

    pub(crate) fn get_one(
        &self,
        resource: &str,
        id: &str,
        include: Option<&str>,
        fields: Option<(&str, &str)>,
    ) -> ApiResponse {
        Self::validate_path_segment(resource, "resource");
        Self::validate_path_segment(id, "id");
        let url = self.url(&format!("/{resource}/{id}"));
        let mut req = self.agent.get(&url);
        req = self.attach_auth(req);
        if let Some(include) = include {
            Self::validate_query_value(include, "include");
            req = req.query("include", include);
        }
        if let Some((type_, f)) = fields {
            Self::validate_path_segment(type_, "fields type");
            req = req.query(format!("fields[{type_}]"), f);
        }
        send(req.call(), &url)
    }

    pub(crate) fn create(&self, resource: &str, data: &Value) -> ApiResponse {
        Self::validate_path_segment(resource, "resource");
        self.write(WriteMethod::Post, &format!("/{resource}"), Some(data))
    }

    pub(crate) fn update(&self, resource: &str, id: &str, data: &Value) -> ApiResponse {
        Self::validate_path_segment(resource, "resource");
        Self::validate_path_segment(id, "id");
        self.write(WriteMethod::Patch, &format!("/{resource}/{id}"), Some(data))
    }

    pub(crate) fn delete_one(&self, resource: &str, id: &str) -> ApiResponse {
        Self::validate_path_segment(resource, "resource");
        Self::validate_path_segment(id, "id");
        let url = self.url(&format!("/{resource}/{id}"));
        let mut req = self.agent.delete(&url);
        req = self.attach_auth(req);
        req = req.header("Content-Type", "application/vnd.api+json");
        send(req.call(), &url)
    }

    /// Resource create/update/delete. Sends `application/vnd.api+json` or the
    /// API 415s. `data: None` sends `{"data": null}` (a valid JSON:API
    /// envelope), not a bare `null`; use `raw_post`/`raw_put` for a truly empty
    /// body.
    fn write(&self, method: WriteMethod, path: &str, data: Option<&Value>) -> ApiResponse {
        let body = serde_json::json!({ "data": data });
        // `expect()`: serializing a `serde_json::Value` is infallible in
        // practice, not a real recoverable runtime case.
        let bytes =
            serde_json::to_vec(&body).expect("serializing a serde_json::Value always succeeds");

        let url = self.url(path);
        let mut req = match method {
            WriteMethod::Post => self.agent.post(&url),
            WriteMethod::Patch => self.agent.patch(&url),
            WriteMethod::Put => self.agent.put(&url),
        };
        req = self.attach_auth(req);
        req = req.header("Content-Type", "application/vnd.api+json");
        send(req.send(&bytes[..]), &url)
    }

    /// "Hit an arbitrary path" primitive for endpoints outside the standard
    /// list/get shape (GET /me, .../stats). Backs `klaay call` and is reused by
    /// `whoami`/`print_status`/`schema::fetch_spec`. Takes `HttpMethod` so an
    /// unsupported method fails at compile time. Unlike the resource methods,
    /// `path` gets no charset validation - it's the documented escape hatch for
    /// arbitrary paths; the host can't change and the server enforces its own
    /// authorization.
    pub(crate) fn call(&self, method: HttpMethod, path: &str, data: Option<&Value>) -> ApiResponse {
        // Informational, not blocking - `path` is the caller's own CLI argument
        // against their own tenant (like a raw `curl`); a `?`/`#` is a
        // legitimate query/fragment, but flag it so it's not a surprise.
        if path.contains('?') || path.contains('#') {
            eprintln!(
                "Note: {path} contains \"?\" or \"#\" - it will be forwarded verbatim as part of the URL."
            );
        }
        let full_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        match method {
            HttpMethod::Get => {
                let url = self.url(&full_path);
                let mut req = self.agent.get(&url);
                req = self.attach_auth(req);
                send(req.call(), &url)
            }
            HttpMethod::Delete => {
                // `main.rs` guards `--data` on DELETE at the CLI layer, but a
                // programmatic caller (library/test/AI-agent, per this method's
                // doc) bypasses that. A real `assert!`, not `debug_assert!`, so
                // a release build doesn't silently drop their DELETE body.
                assert!(
                    data.is_none(),
                    "HttpMethod::Delete does not send a body; the data argument is silently ignored"
                );
                let url = self.url(&full_path);
                let mut req = self.agent.delete(&url);
                req = self.attach_auth(req);
                // Kiln 415s a jsonapi_resources DELETE without this header,
                // same as `delete_one()`.
                req = req.header("Content-Type", "application/vnd.api+json");
                send(req.call(), &url)
            }
            HttpMethod::Post => self.call_write(WriteMethod::Post, &full_path, data),
            HttpMethod::Patch => self.call_write(WriteMethod::Patch, &full_path, data),
            HttpMethod::Put => self.call_write(WriteMethod::Put, &full_path, data),
        }
    }

    /// `call()`'s POST/PATCH/PUT body handling, deliberately distinct from
    /// `write()`: `call()` targets endpoints outside the resource surface, so
    /// it sends the caller's `--data` verbatim rather than wrapping it in a
    /// `{"data": ...}` envelope, and sends no body at all when `data` is `None`.
    fn call_write(&self, method: WriteMethod, path: &str, data: Option<&Value>) -> ApiResponse {
        let url = self.url(path);
        let mut req = match method {
            WriteMethod::Post => self.agent.post(&url),
            WriteMethod::Patch => self.agent.patch(&url),
            WriteMethod::Put => self.agent.put(&url),
        };
        req = self.attach_auth(req);
        match data {
            Some(v) => {
                // Only when a body is sent - an action-only endpoint may need
                // no `--data`, and claiming this content-type on an empty body
                // makes a jsonapi_resources endpoint 400 on empty-string parse.
                req = req.header("Content-Type", "application/vnd.api+json");
                let bytes =
                    serde_json::to_vec(v).expect("serializing a serde_json::Value always succeeds");
                send(req.send(&bytes[..]), &url)
            }
            // `req.send(())` - a `WithBody` builder has no `.call()`; `()` is
            // its explicitly-empty body.
            None => send(req.send(()), &url),
        }
    }

    /// Low-level POST for endpoints outside the JSON:API surface - backs the
    /// ActiveStorage direct-upload protocol (upload.rs). Attaches the bearer
    /// token only when `url` is same-origin with `base_url` (parsed, not a
    /// prefix check that `https://api.example.com.evil.com` would pass), so a
    /// future caller forwarding an external URL can't leak it. Header values
    /// are `&str` since every caller already holds them alive.
    pub(crate) fn raw_post(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> ApiResponse {
        // Defense-in-depth: callers build `url` from the already-validated
        // `base_url_trimmed()`, so this never fires today - but reject non-http
        // (`file://` etc.) loudly rather than let ureq attempt it.
        if !url.starts_with("https://") && !url.starts_with("http://") {
            eprintln!("Error: raw_post URL must use http or https scheme: {url}");
            std::process::exit(1);
        }
        // Redirects disabled (same as `raw_put`) - both callers attach the
        // bearer token, so following a redirect to an attacker URL would
        // forward `Authorization` to it (SSRF-via-redirect).
        let mut req = self.agent.post(url).config().max_redirects(0).build();
        match check_origin(self.base_url_trimmed(), url) {
            OriginCheck::Same => {
                req = self.attach_auth(req);
            }
            // No `starts_with` fallback - a prefix match can't confirm
            // same-origin (see `check_origin`). Unexpected today; when it
            // happens the request goes out unauthenticated (likely a 401).
            OriginCheck::Different => {
                eprintln!(
                    "Warning: could not confirm {url} is the same server as {} - sending this request without the Authorization header (a 401 response likely follows).",
                    self.base_url_trimmed()
                );
            }
            // Both URLs are already http(s) and `url`-parseable by here, so a
            // parse failure means a depended-on assumption broke - hard error
            // rather than a silent unauthenticated send.
            OriginCheck::ParseError => {
                eprintln!(
                    "Error: could not parse {url} or {} to check same-origin - refusing to send this request.",
                    self.base_url_trimmed()
                );
                std::process::exit(1);
            }
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        send(req.send(body), url)
    }

    /// Low-level PUT with no auth - blob-storage direct-upload URLs are
    /// pre-signed and carry their own auth. Header values are owned
    /// `(String, String)` since the one caller (upload.rs) already holds them
    /// that way.
    pub(crate) fn raw_put(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> ApiResponse {
        // Same defense-in-depth scheme guard as `raw_post`.
        if !url.starts_with("https://") && !url.starts_with("http://") {
            eprintln!("Error: raw_put URL must use http or https scheme: {url}");
            std::process::exit(1);
        }
        // Per-request timeout override: this body can be up to 26MB
        // (upload::MAX_UPLOAD_BYTES), and the shared 60s default only covers a
        // ~440KB/s transfer. Scaled by payload size so a small file on a dead
        // connection still fails quickly.
        const MIN_UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        // 100KB/s conservative throughput floor, doubled for headroom (~520s at
        // the 26MB cap). Capped at the high end too: `raw_put` is a
        // `pub(crate)` escape hatch that doesn't enforce MAX_UPLOAD_BYTES, so
        // an oversized body would otherwise scale this to an infinite hang.
        const MAX_UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
        // `Duration::from_secs_f64` panics on a negative or non-finite value, so
        // check those first. The upper bound is a business ceiling (a huge body
        // shouldn't scale into an hours-long timeout), not a `Duration` range
        // guard - `Duration::MAX` is ~5.84e11s, far above `MAX_UPLOAD_TIMEOUT`.
        // Any failing case falls back to the cap.
        let secs = (body.len() as f64 / (100.0 * 1024.0)) * 2.0;
        let upload_timeout =
            if secs.is_finite() && secs >= 0.0 && secs <= MAX_UPLOAD_TIMEOUT.as_secs_f64() {
                MIN_UPLOAD_TIMEOUT.max(std::time::Duration::from_secs_f64(secs))
            } else {
                MAX_UPLOAD_TIMEOUT
            };
        // Redirects disabled for this request only - upload.rs's SSRF guard
        // checks only the initial URL, so a redirect to a private/loopback
        // address at the blob-storage level would otherwise bypass it.
        let mut req = self
            .agent
            .put(url)
            .config()
            .max_redirects(0)
            .timeout_global(Some(upload_timeout))
            .build();
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        send(req.send(body), url)
    }
}

/// Distinguishes "confirmed different origin" (raw_post still sends,
/// unauthenticated) from "couldn't parse a URL" (a hard error, since these
/// URLs should always be parseable).
enum OriginCheck {
    Same,
    Different,
    ParseError,
}

/// `Same` when `a` and `b` share scheme, host, and port - decides whether to
/// attach the bearer token to a caller-supplied URL. Parses via the `url` crate
/// rather than a prefix check a hostname like `base.evil.com` could slip past.
fn check_origin(a: &str, b: &str) -> OriginCheck {
    let (Ok(a), Ok(b)) = (url::Url::parse(a), url::Url::parse(b)) else {
        return OriginCheck::ParseError;
    };
    // `port_or_known_default()` is `None` for a scheme the `url` crate doesn't
    // know; requiring both to be `Some` stops two such URLs comparing
    // `None == None` as a false port match.
    let (Some(port_a), Some(port_b)) = (a.port_or_known_default(), b.port_or_known_default())
    else {
        return OriginCheck::ParseError;
    };
    if a.scheme() == b.scheme() && a.host() == b.host() && port_a == port_b {
        OriginCheck::Same
    } else {
        OriginCheck::Different
    }
}

/// `url` is only for diagnostics: a transport-level failure (connection
/// refused, DNS, TLS) otherwise prints with no indication of which server -
/// local dev vs production - the CLI was actually talking to.
fn send(result: Result<ureq::http::Response<ureq::Body>, ureq::Error>, url: &str) -> ApiResponse {
    match result {
        Ok(mut response) => {
            let status = response.status().as_u16();
            // Read before the body is consumed. A 404 with a `text/html` body is
            // an unrouted path; compare only the media type (not parameters) and
            // without allocating a lowercased copy.
            let is_unrouted_404 = status == 404
                && response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|ct| ct.split(';').next().unwrap_or("").trim())
                    .is_some_and(|mime| mime.eq_ignore_ascii_case("text/html"));
            let text = response.body_mut().read_to_string().unwrap_or_else(|e| {
                eprintln!("Failed to read response body: {e}");
                std::process::exit(1);
            });
            if text.trim().is_empty() {
                // An empty body carries no diagnostic: even a 404 with a
                // text/html content-type but no content (a proxy/CDN health
                // check, say) isn't grounds to claim the path is unrouted, and
                // there'd be no page to point the hint at. `Empty` (not `Json`)
                // so a 204 isn't mistaken for a genuine JSON `null`, and so
                // `UnroutedHtml404` only ever occurs on the non-empty arm below,
                // where the preview is always printed.
                return ApiResponse {
                    status,
                    body: Value::Null,
                    kind: BodyKind::Empty,
                };
            }
            match serde_json::from_str(&text) {
                // A `text/html` 404 whose body still parses as JSON (a proxy
                // wrapping its error, say) is deliberately kept as `Json`, not
                // `UnroutedHtml404`: the parsed body is concrete output worth
                // showing, the routing hint is only a guess, and `is_success()`
                // is already false for a 404 so it surfaces as an error, not as
                // real data.
                Ok(body) => ApiResponse {
                    status,
                    body,
                    kind: BodyKind::Json,
                },
                Err(e) => {
                    // Always show a capped preview so the real body is never
                    // fully hidden - an HTML 404 from a WAF/CDN or proxy carries
                    // its own diagnostic, and the unrouted-path hint below is
                    // only a best guess. Capped at the first ~200 chars so a full
                    // page can't flood the terminal.
                    let (preview, truncated) = match text.char_indices().nth(200) {
                        Some((i, _)) => (&text[..i], "..."),
                        None => (text.as_str(), ""),
                    };
                    eprintln!(
                        "Warning: response body was not valid JSON ({e}): {preview}{truncated}"
                    );
                    // Keep the real status; a non-`Json` kind makes `is_success()`
                    // treat an unparseable 2xx as failure.
                    ApiResponse {
                        status,
                        body: Value::Null,
                        kind: if is_unrouted_404 {
                            BodyKind::UnroutedHtml404
                        } else {
                            BodyKind::ParseFailed
                        },
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Request to {url} failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Prints a JSON:API list response with a "showing N of TOTAL" trailer when
/// meta.total is present. A failed request exits non-zero, same as
/// `print_response`.
pub(crate) fn print_list_response(response: &ApiResponse) {
    // Via the accessors, not the private `body` field, so this stays correct
    // if `ApiResponse` ever moves to another module.
    if !response.is_success() {
        eprintln!("Error {}: {}", response.status, response.error_detail());
        std::process::exit(1);
    }
    // A list endpoint should always return a JSON:API collection body (an empty
    // collection is `{"data":[]}` with 200). A bodyless 2xx is anomalous - most
    // likely a proxy/gateway 204 - so error rather than exit 0 with empty
    // stdout, which a script couldn't tell from a legitimate empty list. (Unlike
    // `print_response`, where a 204 from `call DELETE` is a genuine success.)
    let Some(body) = response.body() else {
        eprintln!(
            "Error {}: list response had no body (expected a JSON:API collection).",
            response.status
        );
        std::process::exit(1);
    };
    // `expect()`: a `Json` body always re-serializes, so a failure should
    // surface loudly, not print nothing with exit 0.
    println!(
        "{}",
        serde_json::to_string_pretty(body)
            .expect("serializing a serde_json::Value always succeeds")
    );
    if let Some(total) = body
        .get("meta")
        .and_then(|m| m.get("total"))
        .and_then(|t| t.as_u64())
    {
        let shown = body
            .get("data")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        println!("showing {shown} of {total}");
    }
}

pub(crate) fn print_response(response: &ApiResponse) {
    if !response.is_success() {
        eprintln!("Error {}: {}", response.status, response.error_detail());
        std::process::exit(1);
    }
    // A 2xx with no body (e.g. a 204 from `call DELETE`) prints nothing, not
    // `null` - a script capturing stdout should get empty output for it.
    if let Some(body) = response.body() {
        println!(
            "{}",
            serde_json::to_string_pretty(body)
                .expect("serializing a serde_json::Value always succeeds")
        );
    }
}

/// Areas averaged into the "overall %" - matches useComplianceData.ts's
/// `overallCompliance` (not the differently-weighted
/// `overallCompliancePercentage` sibling).
const OVERALL_AREAS: &[&str] = &[
    "employees",
    "policies",
    "account_information",
    "controls",
    "risk_scenarios",
];

/// Order and labels mirror ComplianceProgress.vue's areaLabels. Deliberately
/// no "events" row - the UI's "Plan all Events" has no backing area here.
const AREA_ORDER: &[(&str, &str)] = &[
    ("account_information", "Company information"),
    ("employees", "People"),
    ("vendors", "Vendors"),
    ("devices", "Add Assets"),
    ("policies", "Review Policies"),
    ("risk_scenarios", "Add & Review Risks"),
    ("controls", "Add & Review Controls"),
];

/// `klaay status` - GET /compliance_stats, rendered the same way the frontend
/// computes the "Road to Readiness" widget.
pub(crate) fn print_status(client: &ApiClient, json: bool) {
    // Every `OVERALL_AREAS` entry must have an `AREA_ORDER` row, else it would
    // be folded into the overall % without appearing in the per-area table. A
    // real `assert!` (cheap, two tiny constants) so a release build catches it.
    assert!(
        OVERALL_AREAS
            .iter()
            .all(|a| AREA_ORDER.iter().any(|(k, _)| k == a)),
        "every OVERALL_AREAS entry must have a corresponding row in AREA_ORDER"
    );
    let response = client.call(HttpMethod::Get, "/compliance_stats", None);
    if !response.is_success() {
        if response.status == 403 {
            eprintln!("This command requires an admin account - ask your Klaay admin to run it, or log in as one.");
        } else {
            eprintln!("Error {}: {}", response.status, response.error_detail());
        }
        std::process::exit(1);
    }
    let body = response.body().unwrap_or(&Value::Null);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(body)
                .expect("serializing a serde_json::Value always succeeds")
        );
        return;
    }

    // Borrowed, not cloned - `data` is only read below.
    let data: &[Value] = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut percentages: HashMap<String, f64> = HashMap::new();
    let mut totals: HashMap<String, u64> = HashMap::new();

    for item in data {
        let Some(meta) = item.get("meta") else {
            continue;
        };
        // `continue`d, not `""` - a blank area key would be inserted into
        // `percentages`/`totals` and render as a spurious blank-labeled row.
        let Some(area) = meta.get("area").and_then(|v| v.as_str()) else {
            continue;
        };
        let area = area.to_string();
        let total = meta.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        // A `HashSet` - `compliant_states` is server-controlled, and a
        // duplicate would double-count a tally bucket, pushing the percentage
        // over 100%.
        let compliant_states: std::collections::HashSet<String> = meta
            .get("compliant_states")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let tally = meta.get("tally").and_then(|v| v.as_object());
        // `.fold` with `saturating_add`, not `.sum()`, since these are
        // server-controlled and `.sum()` wraps/panics on overflow. Two extra
        // guards, both because the server controls every value: a single
        // bucket exceeding `total` is rejected as corrupt, and the running sum
        // is capped at `total` after each add so several plausible buckets
        // can't together saturate to a misleading 100%.
        let compliant_count: u64 = tally
            .map(|t| {
                compliant_states
                    .iter()
                    .filter_map(|s| t.get(s))
                    // Warn on a non-integer bucket too (same reasoning as the
                    // over-total case below): silently dropping it would look
                    // identical to a genuine 0%.
                    .filter_map(|v| {
                        let n = v.as_u64();
                        if n.is_none() {
                            eprintln!(
                                "Warning: tally bucket for area '{area}' has non-integer value {v} - ignoring it."
                            );
                        }
                        n
                    })
                    // Warned, not silently dropped - a rejected bucket would
                    // otherwise look identical to a genuine 0%.
                    .filter(|&n| {
                        if n > total {
                            eprintln!(
                                "Warning: tally bucket for area '{area}' has value {n} exceeding total {total} - ignoring it."
                            );
                            false
                        } else {
                            true
                        }
                    })
                    .fold(0u64, |acc, n| {
                        let sum = acc.saturating_add(n);
                        // Warned for the same reason - a silent cap would look
                        // identical to a genuinely 100% area.
                        if sum > total {
                            eprintln!(
                                "Warning: tally buckets for area '{area}' sum past total {total} - capping at 100%."
                            );
                        }
                        sum.min(total)
                    })
            })
            .unwrap_or(0);
        let pct = if total > 0 {
            // Clamped as belt-and-suspenders alongside the guards above.
            ((compliant_count as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        percentages.insert(area.clone(), pct);
        totals.insert(area, total);
    }

    // Divides by the constant OVERALL_AREAS.len() (5), matching
    // useComplianceData.ts, not by how many areas came back. A missing area
    // drags the average down, so warn rather than silently understate.
    let missing_areas: Vec<&str> = OVERALL_AREAS
        .iter()
        .filter(|a| !percentages.contains_key(**a))
        .copied()
        .collect();
    if !missing_areas.is_empty() {
        eprintln!(
            "Warning: compliance_stats response is missing areas: {} - overall % may be understated.",
            missing_areas.join(", ")
        );
    }
    let overall_sum: f64 = OVERALL_AREAS
        .iter()
        .filter_map(|a| percentages.get(*a))
        .sum();
    let overall = overall_sum / OVERALL_AREAS.len() as f64;

    // `{:.0}` for consistency with the per-area rows below. `overall` can't be
    // NaN: the divisor is the constant 5, so a fully-missing response is 0.0.
    println!("Overall readiness: {overall:.0}%\n");
    for (area, label) in AREA_ORDER {
        let pct = percentages.get(*area).copied().unwrap_or(0.0);
        let total = totals.get(*area).copied().unwrap_or(0);
        let note = if OVERALL_AREAS.contains(area) {
            ""
        } else {
            "   [not counted in overall]"
        };
        println!("  {label:<24}{pct:>4.0}%   ({total} total){note}");
    }
}
