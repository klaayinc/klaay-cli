use serde_json::Value;
use std::collections::HashMap;

pub(crate) struct ApiClient {
    agent: ureq::Agent,
    base_url: String,
    // The full `"Bearer <token>"` header value, validated and built once in
    // `new()` rather than re-validated and re-allocated on every request -
    // `bearer()` used to do both on every single call (`list`/`get_one`/
    // `write`/`call`/`raw_post`, 7 call sites), which is pure overhead once
    // per request for a value that can never change over `self`'s lifetime
    // (`token` has no setter, so nothing could invalidate this between
    // calls). Precomputing here means an invalid stored token is now
    // reported at client construction (as soon as the command starts)
    // instead of on whichever request happens to run first.
    //
    // Zeroized on drop, same as every other bearer credential this codebase
    // handles (password, id_token, StoredToken.token) - every caller that
    // constructs an ApiClient from a stored/derived token was previously
    // passing a plain String clone/to_string() copy that lingered
    // unprotected in memory until this struct dropped.
    //
    // Private (no `pub(crate)`) rather than exposed directly - confirmed via
    // grep that nothing outside this module reads it, and keeping it
    // private closes off `client.auth_header.clone()` (an unzeroized copy)
    // or `client.auth_header.take()` (which would move the value out and
    // prevent this struct's own Drop from zeroing it) from any future
    // crate-internal caller. `bearer()` is the only sanctioned way to read
    // it.
    auth_header: Option<zeroize::Zeroizing<String>>,
}

pub(crate) struct ApiResponse {
    pub(crate) status: u16,
    // Private (not `pub(crate)`) - see `body()`/`raw_body()`/`into_raw_body()`
    // below. A caller reading this field directly could easily mistake a
    // parse-failure placeholder (`Value::Null`) for the server genuinely
    // returning `null`, without ever checking `is_success()`/`json_parse_
    // failed` first - confirmed this was already happening at 2 real call
    // sites (auth.rs's `login_with_credentials`, upload.rs's
    // `direct_upload`), which checked a raw status range instead of
    // `is_success()` before trusting this field.
    body: Value,
    // Set when a 2xx response's body wasn't valid JSON (see `send()`) -
    // `is_success()` treats this as failure without needing to overwrite
    // `status` with a synthetic code, so callers that check `status` for a
    // specific real value (e.g. `print_status`'s `403` check) still see the
    // server's actual status.
    json_parse_failed: bool,
}

/// The HTTP methods `klaay call` actually supports. Deliberately has no
/// `clap` derive here (unlike an earlier version of this enum) - this is the
/// HTTP client layer, and coupling it to the CLI argument-parsing framework
/// would mean any future non-clap consumer of `ApiClient` (a library user, a
/// test harness, a WASM port) pulls in `clap` too, for no benefit to that
/// consumer. `main.rs` defines a thin `CliHttpMethod` wrapper with the actual
/// `#[derive(clap::ValueEnum)]` and converts to this type via `From` -
/// `call()` below still takes this type directly (not a raw `&str`), so a
/// crate-internal caller that bypassed clap entirely still gets a compile
/// error for an unsupported method instead of a runtime `process::exit`.
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

/// The 3 HTTP methods `write()` actually implements. `ureq::http::Method` is
/// non-exhaustive (it covers every HTTP method, including ones like HEAD/
/// OPTIONS this client never sends), so matching on it directly forced a
/// catch-all `other` arm that could only fail at runtime via `process::exit`
/// even though every real call site already only ever passes POST/PATCH/PUT.
/// This local enum makes that a compile-time guarantee instead - there's no
/// variant to construct that `write()`'s match doesn't handle.
enum WriteMethod {
    Post,
    Patch,
    Put,
}

impl ApiResponse {
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status) && !self.json_parse_failed
    }

    /// The parsed body, or `None` if the response body wasn't valid JSON -
    /// distinguishing that from the server genuinely returning `null`. The
    /// call site this forces: check `is_success()` (or match on this
    /// directly) before treating the body as real data.
    pub(crate) fn body(&self) -> Option<&Value> {
        if self.json_parse_failed {
            None
        } else {
            Some(&self.body)
        }
    }

    /// The body regardless of parse success - `Value::Null` on failure. Only
    /// for diagnostic/error-display call sites that already know (via
    /// `!is_success()`) this may not be real data and just need *something*
    /// to show the user.
    pub(crate) fn raw_body(&self) -> &Value {
        &self.body
    }

    /// Consuming counterpart of `raw_body()` - for call sites past their own
    /// `is_success()` check that need to move the body out (e.g. to return
    /// it as an owned value) rather than borrow it.
    pub(crate) fn into_raw_body(self) -> Value {
        self.body
    }

    /// A human-readable rendering of the body for error-display call sites.
    /// `raw_body()` alone is `Value::Null` in two different situations - a
    /// genuinely empty response, and a non-empty response that failed to
    /// parse as JSON (`send()` already prints a "Warning: response body was
    /// not valid JSON" line with a preview of the real body in that second
    /// case) - and `serde_json::to_string`ing it either way prints the bare
    /// string `"null"`, which reads as "no error detail exists" even when
    /// `send()`'s warning just showed the real, non-JSON detail a line above.
    /// This distinguishes the two so a failure with an actual (non-JSON)
    /// body doesn't look indistinguishable from one with none at all.
    pub(crate) fn error_detail(&self) -> String {
        if self.json_parse_failed {
            "(response body was not valid JSON - see warning above)".to_string()
        } else {
            serde_json::to_string(&self.body).unwrap_or_default()
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
        // Non-2xx responses still deserialize as JSON:API error bodies rather
        // than becoming an opaque ureq::Error - see the client.rs research note.
        // timeout_connect/timeout_global bound how long a hung or
        // slow-to-respond server can block the process - with no timeout at
        // all, a single stuck request would hang the CLI indefinitely.
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(std::time::Duration::from_secs(10)))
            .timeout_global(Some(std::time::Duration::from_secs(60)))
            .build();
        ApiClient {
            agent: ureq::Agent::new_with_config(config),
            base_url,
            auth_header: token.map(Self::build_auth_header),
        }
    }

    /// Validates and formats the `"Bearer <token>"` header value - see the
    /// `auth_header` field's doc comment for why this runs once here rather
    /// than on every request. Exits the process outright (rather than
    /// silently proceeding unauthenticated) if `token` contains anything
    /// outside the actual JWT character set (base64url alphanumerics, `-`,
    /// `_`, `.`). A token with embedded control characters, spaces, or other
    /// non-JWT bytes means the credentials file/keyring entry is corrupted;
    /// every call site that reads `auth_header` just does
    /// `if let Some(auth) = self.bearer() { attach it }`, so a `None` here
    /// would silently downgrade to an unauthenticated request instead of
    /// surfacing the real problem - if the endpoint happens to be publicly
    /// reachable, the caller would get a normal-looking response with no
    /// indication the credential was discarded.
    ///
    /// Takes `t: Zeroizing<String>` by value, not `&str` - an earlier version
    /// took a borrow, which meant this function could only validate, never
    /// zero, since it never owned the buffer; `new()`'s caller (`token.map(|t|
    /// ...)`) still had the real owned `Zeroizing` alive one frame up, and
    /// `process::exit` from inside the borrow-taking call skipped that
    /// frame's `Drop` too, so the token was never actually cleared. Owning
    /// `t` here means the invalid-input exit path can explicitly zero the
    /// real buffer first, matching `auth::require_login`'s equivalent check.
    fn build_auth_header(mut t: zeroize::Zeroizing<String>) -> zeroize::Zeroizing<String> {
        // Tightened to the actual JWT character set (base64url
        // alphanumerics, `-`, `_`, the `.` separators) - matches
        // `auth::require_login`'s equivalent check. `is_ascii_graphic()`
        // (all of visible ASCII 0x21-0x7E) would still accept characters
        // like `"`, `#`, `[`, `\`, `,` that are illegal in a JWT but would
        // reach ureq's header API verbatim inside the `Authorization` value
        // if this check were ever the only thing standing in the way.
        if !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            eprintln!("Stored token contains invalid characters - run `klaay login` again.");
            zeroize::Zeroize::zeroize(&mut *t);
            std::process::exit(1);
        }
        // `Zeroizing::new(String::with_capacity(...))` + `push_str` twice,
        // not `Zeroizing::new(format!("Bearer {}", ...))` - matches
        // `auth.rs`'s `build_secret_auth_body`'s own documented reasoning
        // for avoiding this exact pattern: `format!` first produces an
        // ordinary, unprotected heap-allocated `String`, and `Zeroizing::new`
        // only starts protecting it *after* that allocation already exists -
        // a move into the wrapper doesn't retroactively zero whatever the
        // allocator did during `format!`'s own internal growth. Building the
        // string directly inside the already-`Zeroizing`-wrapped buffer
        // means there's never a moment where "Bearer <token>" exists in a
        // plain, unprotected allocation.
        let mut header = zeroize::Zeroizing::new(String::with_capacity("Bearer ".len() + t.len()));
        header.push_str("Bearer ");
        header.push_str(t.as_str());
        header
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url_trimmed(), path)
    }

    /// `url()` builds the request path via plain string concatenation onto
    /// `base_url` - a whitelist (alphanumerics, `-`, `_`) rather than a
    /// blocklist of just `/` and `..`, since a resource type is a single
    /// JSON:API type name and an id is a bare numeric/UUID value, neither of
    /// which ever legitimately needs any other character. A blocklist of
    /// only `/`/`..` would still let `?`/`#` inject a query string or
    /// fragment (e.g. an id of `101?admin=true`), a percent-encoded `%2F`
    /// slip past the literal `/` check and be decoded server-side, or a
    /// null byte reach whatever HTTP stack processes it - a whitelist closes
    /// all of those at once instead of enumerating blocked characters
    /// one-by-one as they're discovered.
    pub(crate) fn validate_path_segment(value: &str, name: &str) {
        // Checked explicitly, not left to the character-set check below -
        // `.chars().all(...)` is vacuously true over zero characters, so an
        // empty `value` would otherwise pass straight through and produce a
        // URL like `/resource/` or `//`, matching a broader server route or
        // producing a confusing error instead of a clear client-side one.
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

    /// Same whitelist spirit as `validate_path_segment` above, but for
    /// `sort`/`include` query values rather than path segments - these
    /// legitimately contain commas (multiple fields: `sort=-name,created_at`)
    /// and dots (nested relationships: `include=owners.user`), and `sort`
    /// values are prefixed with `-` for descending order, none of which
    /// `validate_path_segment`'s stricter charset permits. `req.query()` is
    /// already confirmed (same TCP-capture check noted on the filter-key
    /// validation above) to percent-encode these values regardless, so this
    /// isn't closing a live vulnerability - but the filter/fields-type
    /// values right next to these already get an explicit whitelist rather
    /// than resting on that downstream encoding alone, and these two
    /// user-supplied values (from `--sort`/`--include`) shouldn't be the odd
    /// ones out.
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

    /// Trivial accessor over the precomputed `auth_header` (see that field's
    /// doc comment) - all the validation and formatting already happened
    /// once in `new()`, so this is just a borrow, not a per-request
    /// allocation.
    fn bearer(&self) -> Option<&zeroize::Zeroizing<String>> {
        self.auth_header.as_ref()
    }

    /// Centralizes the `if let Some(auth) = self.bearer() { attach it }`
    /// pattern that was previously repeated at every request-building call
    /// site (`list`, `get_one`, `delete_one`, `write`, `call`'s two arms,
    /// `call_write`, `raw_post`) - a future method that built a request
    /// without going through this helper would visibly skip attaching auth,
    /// rather than silently omitting a copy-pasted `if let` block with
    /// nothing to catch the omission. Generic over `B` (`ureq`'s
    /// `WithBody`/`WithoutBody` request-builder states) since `.header()` is
    /// defined the same way regardless of which one a given HTTP method's
    /// builder starts as.
    fn attach_auth<B>(&self, req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        if let Some(auth) = self.bearer() {
            req.header("Authorization", auth.as_str())
        } else {
            req
        }
    }

    /// Normalized base URL (trailing slash trimmed) for callers outside this
    /// module that need to build a URL themselves - e.g. upload.rs's
    /// ActiveStorage direct-upload endpoint, which isn't a JSON:API resource
    /// path this client's own methods can express. Centralizes the trimming
    /// so it isn't duplicated at each such call site.
    pub(crate) fn base_url_trimmed(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// GET a collection with JPie-correct filter/sort/include/fields/page encoding.
    /// A filter key that appears once serializes as `filter[key]=value`; a key
    /// repeated across multiple --filter flags serializes as `filter[key][]=value`
    /// for each occurrence, since Kiln's `_include`-style scopes expect a real
    /// array and silently match nothing against a comma-joined string.
    pub(crate) fn list(&self, resource: &str, params: &ListParams) -> ApiResponse {
        Self::validate_path_segment(resource, "resource");
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (k, _) in &params.filters {
            *counts.entry(k.as_str()).or_insert(0) += 1;
        }

        let mut req = self.agent.get(self.url(&format!("/{resource}")));
        req = self.attach_auth(req);

        for (k, v) in &params.filters {
            // Same character-set check as `resource` above - JSON:API filter
            // scope names are always valid Ruby identifiers (alphanumerics
            // and underscores) in practice, so this costs nothing on any real
            // filter key. `req.query()` was already confirmed (via a real TCP
            // capture) to percent-encode the whole `filter[...]`/
            // `filter[...][]` string regardless, so this isn't closing a live
            // vulnerability - but that safety was resting entirely on an
            // internal implementation detail of ureq's own query-encoding
            // rather than an explicit guarantee this code makes for itself.
            Self::validate_path_segment(k, "filter key");
            // `.get()` rather than the `Index` operator - the construction
            // loop above guarantees every key here is present, but that's an
            // implicit invariant between two loops; a `.get()` miss just
            // yields the same "singular" formatting instead of a panic if
            // that invariant were ever broken by a future refactor.
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
            // Same character-set guard as the filter keys above - `type_` is
            // interpolated into the query key the same way `k` is.
            Self::validate_path_segment(type_, "fields type");
            req = req.query(format!("fields[{type_}]"), fields);
        }
        if let Some(n) = params.page_number {
            req = req.query("page[number]", n.to_string());
        }
        if let Some(n) = params.page_size {
            req = req.query("page[size]", n.to_string());
        }

        send(req.call())
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
        let mut req = self.agent.get(self.url(&format!("/{resource}/{id}")));
        req = self.attach_auth(req);
        if let Some(include) = include {
            Self::validate_query_value(include, "include");
            req = req.query("include", include);
        }
        if let Some((type_, f)) = fields {
            Self::validate_path_segment(type_, "fields type");
            req = req.query(format!("fields[{type_}]"), f);
        }
        send(req.call())
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
        let mut req = self.agent.delete(self.url(&format!("/{resource}/{id}")));
        req = self.attach_auth(req);
        req = req.header("Content-Type", "application/vnd.api+json");
        send(req.call())
    }

    /// Every resource create/update/delete needs `application/vnd.api+json` or
    /// the API 415s (confirmed against the jpie gem's ensure_jsonapi_content_type
    /// before_action, which only fires for jsonapi_resources controllers).
    /// `data: None` (only possible via `call()`, when invoked with no `--data`)
    /// sends a literal `{"data": null}` body - a parseable JSON:API envelope
    /// with a null resource, not a bare top-level `null` a Rails controller's
    /// JSON parsing would likely choke on. If an endpoint needs a genuinely
    /// empty body instead, use `raw_post`/`raw_put`.
    fn write(&self, method: WriteMethod, path: &str, data: Option<&Value>) -> ApiResponse {
        let body = serde_json::json!({ "data": data });
        // `expect()`, not `process::exit` - `body` is a `json!({ "data": ... })`
        // wrapping a `serde_json::Value` the caller already validated is
        // representable (or `None`), and serde_json::Value serialization is
        // infallible in practice; presenting this as a recoverable runtime
        // exit misrepresents a provably-unreachable case as if it could
        // legitimately occur.
        let bytes =
            serde_json::to_vec(&body).expect("serializing a serde_json::Value always succeeds");

        let mut req = match method {
            WriteMethod::Post => self.agent.post(self.url(path)),
            WriteMethod::Patch => self.agent.patch(self.url(path)),
            WriteMethod::Put => self.agent.put(self.url(path)),
        };
        req = self.attach_auth(req);
        req = req.header("Content-Type", "application/vnd.api+json");
        send(req.send(&bytes[..]))
    }

    /// Generic "hit an arbitrary path" primitive for endpoints that aren't a
    /// standard list/get(resource,id) shape (GET /me, .../stats, etc). This is
    /// what backs the `klaay call` subcommand directly, and what `whoami`,
    /// `print_status`, and `schema::fetch_spec` build on internally rather
    /// than duplicating request plumbing.
    /// Takes `HttpMethod` (defined above), not a raw `&str` - the previous
    /// `&str` signature meant a *compiling* future crate-internal caller that
    /// bypassed clap's `ValueEnum` validation could still reach the runtime
    /// `process::exit` in an `other` catch-all arm for an unsupported method.
    /// With `HttpMethod`, that arm can't exist at all - every variant is
    /// handled below, so the match is exhaustive at compile time.
    ///
    /// Unlike `list`/`get_one`/`create`/`update`/`delete_one`, `path` here
    /// deliberately gets none of `validate_path_segment`'s character
    /// restrictions - this is the documented low-level escape hatch for
    /// paths that don't fit the `resource`/`id` shape those methods assume
    /// (e.g. `/me`, `/selected_risk_scenarios/stats`), so it has to accept
    /// arbitrary path strings, including a leading `/` for a multi-segment
    /// path. The destination host still can't change (`self.url(path)` below
    /// always builds against `self.base_url`), and the server enforces its
    /// own authorization on whatever path is actually reached - callers
    /// relying on this method are trusted to supply a sane path themselves,
    /// the same way a developer typing a raw `curl` URL would be.
    pub(crate) fn call(&self, method: HttpMethod, path: &str, data: Option<&Value>) -> ApiResponse {
        // Informational, not blocking - `path` here comes straight from the
        // `klaay call` subcommand's own CLI argument, typed (or generated,
        // for an AI-agent caller) by whoever is running this binary with
        // their own credentials against their own tenant; there's no
        // cross-trust-boundary for this escape hatch to defend, the same as
        // a raw `curl` invocation. A `?`/`#` in `path` isn't rejected -
        // this method has to accept it, since `/selected_risk_scenarios/
        // stats?foo=bar`-shaped calls are legitimate uses of this exact
        // escape hatch - but a one-line heads-up avoids surprise for anyone
        // who assumed query params needed a separate flag.
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
                let mut req = self.agent.get(self.url(&full_path));
                req = self.attach_auth(req);
                send(req.call())
            }
            HttpMethod::Delete => {
                // `data` is silently ignored for DELETE - `main.rs`'s CLI
                // entry point already guards against a user passing --data
                // here with a clear error, but that guard lives at the CLI
                // layer, not here at the `call()` API boundary itself. This
                // catches a programmatic caller (a future library user, test
                // harness, or AI-agent caller bypassing the CLI layer
                // entirely - all explicitly named as potential `ApiClient`
                // consumers in this method's own doc comment) passing
                // `Some(data)` here, where the Post/Patch/Put arms above
                // would serialize and send it but this one just drops it.
                // A real `assert!`, not `debug_assert!` - this method's own
                // doc comment names library users, test harnesses, and
                // AI-agent callers as legitimate `ApiClient` consumers who
                // bypass `main.rs`'s CLI-layer guard entirely, so a release
                // build silently dropping their DELETE body with zero
                // diagnostic (which `debug_assert!` alone would do, being
                // compiled away outside debug builds) is exactly the failure
                // mode this check exists to prevent for that audience.
                assert!(
                    data.is_none(),
                    "HttpMethod::Delete does not send a body; the data argument is silently ignored"
                );
                let mut req = self.agent.delete(self.url(&full_path));
                req = self.attach_auth(req);
                // Kiln's ensure_jsonapi_content_type before_action 415s a
                // jsonapi_resources DELETE without this header too, same as
                // delete_one() above - `klaay call DELETE /...` routes through
                // here, so it needs it as well.
                req = req.header("Content-Type", "application/vnd.api+json");
                send(req.call())
            }
            HttpMethod::Post => self.call_write(WriteMethod::Post, &full_path, data),
            HttpMethod::Patch => self.call_write(WriteMethod::Patch, &full_path, data),
            HttpMethod::Put => self.call_write(WriteMethod::Put, &full_path, data),
        }
    }

    /// `call()`'s own POST/PATCH/PUT body handling - deliberately distinct
    /// from `write()` above rather than reusing it. `write()` always wraps
    /// `data` in a `{"data": ...}` JSON:API envelope because `create()`/
    /// `update()` always target a `jsonapi_resources` endpoint, where that
    /// shape is mandatory. `call()` is documented as the low-level escape
    /// hatch for endpoints *outside* that resource surface (e.g. a bespoke
    /// controller action) - unconditionally applying the same wrapping here
    /// would silently corrupt a caller's `--data` payload aimed at an
    /// endpoint that expects a raw, unwrapped JSON body. This sends exactly
    /// what the caller passed, or no body at all when `data` is `None`
    /// (rather than `write()`'s literal `{"data": null}`, which only makes
    /// sense as a valid JSON:API envelope shape, not as "no body").
    fn call_write(&self, method: WriteMethod, path: &str, data: Option<&Value>) -> ApiResponse {
        let mut req = match method {
            WriteMethod::Post => self.agent.post(self.url(path)),
            WriteMethod::Patch => self.agent.patch(self.url(path)),
            WriteMethod::Put => self.agent.put(self.url(path)),
        };
        req = self.attach_auth(req);
        match data {
            Some(v) => {
                // Only set when a body is actually being sent - `klaay call`
                // doesn't require `--data` for POST/PATCH/PUT (an action-only
                // endpoint may need no body at all), and sending this header
                // unconditionally alongside `req.send(())` meant a
                // jsonapi_resources endpoint reached via this escape hatch
                // with no `--data` would try to JSON-parse an empty string
                // and 400 with an opaque parser error, instead of the empty
                // body just being sent as-is with no content-type claim.
                req = req.header("Content-Type", "application/vnd.api+json");
                let bytes =
                    serde_json::to_vec(v).expect("serializing a serde_json::Value always succeeds");
                send(req.send(&bytes[..]))
            }
            // `req.send(())` - a `RequestBuilder<WithBody>` (what
            // `self.agent.post/patch/put` returns) has no `.call()` method;
            // that only exists on `RequestBuilder<WithoutBody>` (GET/DELETE
            // above). `()` implements `AsSendBody` as an explicitly empty
            // body, the `WithBody` builder's equivalent of "no body".
            None => send(req.send(())),
        }
    }

    /// Low-level POST for endpoints outside the JSON:API resource surface -
    /// backs the ActiveStorage direct-upload protocol (upload.rs), which needs
    /// its own headers/body shape rather than the `{"data": ...}` envelope.
    /// Attaches this client's own bearer token automatically, same as every
    /// other method here - but only when `url` is actually same-origin with
    /// this client's `base_url` (scheme + host + port all match), so a
    /// caller passing some other host (today `upload.rs` always passes
    /// `base_url_trimmed() + "/rails/active_storage/..."`, but this guards
    /// against a future call site accidentally forwarding an
    /// externally-supplied URL) can't leak the bearer token to a third
    /// party. A plain `starts_with` prefix check here would be a real bug:
    /// `https://api.example.com.evil.com` also starts with
    /// `https://api.example.com`, so this parses both URLs and compares the
    /// actual origin components instead.
    ///
    /// Takes `&str` header values (not owned `String`s), matching
    /// `raw_put` below - every caller already holds its header values alive
    /// for the duration of the call, so requiring owned `String`s here
    /// only forced an unnecessary clone/allocation at each call site with
    /// no corresponding benefit.
    pub(crate) fn raw_post(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> ApiResponse {
        // Defense-in-depth: both current call sites always build `url` from
        // `base_url_trimmed()` (itself already validated by
        // `config::enforce_secure`), so this never fires today - but
        // rejecting anything other than http(s) here means a future call
        // site accidentally passing a `file://` or other custom-scheme URL
        // fails loudly instead of `self.agent.post` silently attempting
        // whatever that scheme does.
        if !url.starts_with("https://") && !url.starts_with("http://") {
            eprintln!("Error: raw_post URL must use http or https scheme: {url}");
            std::process::exit(1);
        }
        // Redirects disabled, same as `raw_put` below - this is used by
        // `auth.rs`'s `/authenticate` call and `upload.rs`'s direct-upload
        // setup request, both of which attach the bearer token when
        // `check_origin` returns `Same`. Without this, a compromised or
        // misconfigured server could return a redirect to an
        // attacker-controlled URL and have `Authorization: Bearer <token>`
        // forwarded to it - the exact SSRF-via-redirect class `raw_put`'s
        // own guard already closes for the upload PUT itself.
        let mut req = self.agent.post(url).config().max_redirects(0).build();
        match check_origin(self.base_url_trimmed(), url) {
            OriginCheck::Same => {
                req = self.attach_auth(req);
            }
            // No `starts_with` fallback here - a prefix match can't
            // "confirm" same-origin (that's the exact insecure shortcut
            // `check_origin`'s own doc comment exists to avoid, since
            // `https://api.example.com.evil.com` also starts with
            // `https://api.example.com`), so a warning implying it could
            // would be actively misleading. Every real call site today
            // always builds `url` from `base_url_trimmed()` itself, so
            // `check_origin` returning `Different` here is unexpected; when
            // it does, the request still goes out unauthenticated and comes
            // back as a plain 401 with nothing to explain why, since the
            // omission itself is silent.
            OriginCheck::Different => {
                eprintln!(
                    "Warning: could not confirm {url} is the same server as {} - sending this request without the Authorization header (a 401 response likely follows).",
                    self.base_url_trimmed()
                );
            }
            // Unlike `Different`, this means one of the two URLs couldn't
            // even be parsed (or resolved to a known port) - and both are
            // guaranteed http(s) and already `url`-crate-parseable by this
            // point (the scheme check above, and `base_url_trimmed()`
            // already passing through `config::enforce_secure`'s own `url`
            // crate parse). A hard error here, not a silent unauthenticated
            // send: reaching this branch at all means an assumption this
            // function depends on has already broken, and continuing
            // unauthenticated would only trade one confusing failure (a
            // bare 401) for another.
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
        send(req.send(body))
    }

    /// Low-level PUT with no auth attached - blob storage direct-upload URLs
    /// are pre-signed and carry their own auth in the URL/headers Kiln
    /// returns, not our bearer token. Takes `&[(String, String)]` (not
    /// `&[(&str, &str)]`) since the one caller (upload.rs) already holds its
    /// header values in an owned `Vec<(String, String)>` it keeps alive for
    /// the duration of this call - accepting the owned form directly means
    /// that caller doesn't need to first collect a second, borrowed-`&str`
    /// `Vec` just to satisfy this signature.
    pub(crate) fn raw_put(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> ApiResponse {
        // Same defense-in-depth guard as `raw_post` above - `upload.rs`'s
        // `direct_upload` (the sole current caller) already validates the
        // scheme itself before reaching here, so this never fires today, but
        // as a low-level escape-hatch method accepting an arbitrary
        // caller-supplied URL, a future caller that skips that
        // pre-validation would otherwise silently hand a `file://` or other
        // custom-scheme URL straight to `ureq`.
        if !url.starts_with("https://") && !url.starts_with("http://") {
            eprintln!("Error: raw_put URL must use http or https scheme: {url}");
            std::process::exit(1);
        }
        // A per-request `timeout_global` override, larger than
        // `ApiClient::new`'s shared 60s default - that default is sized for
        // ordinary JSON:API calls, but this method's body can be up to
        // `upload::MAX_UPLOAD_BYTES` (26MB), and 60s covers only a ~440KB/s
        // sustained transfer at that size. A slow or congested connection
        // (mobile hotspot, busy office network) hitting the 60s ceiling
        // mid-transfer would abort an otherwise-healthy upload with an
        // opaque "Request failed", indistinguishable from a genuinely dead
        // connection. Scaled by the actual payload size (with a floor
        // matching the shared default) rather than one large fixed value, so
        // a small file still fails within a reasonable time if the
        // connection is actually down, instead of only after several
        // minutes.
        const MIN_UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        // 100KB/s - a conservative sustained-throughput floor representative
        // of a poor/congested connection, not a broadband one - doubled for
        // headroom. At the 26MB cap this works out to about 520s; a typical
        // few-MB evidence file still finishes in well under the 60s floor's
        // worth of actual transfer time.
        //
        // Capped at the high end too - `raw_put` is a `pub(crate)` escape
        // hatch, and `upload::MAX_UPLOAD_BYTES` (26MB) is private to
        // upload.rs and not enforced here, so nothing stops a future caller
        // from passing a much larger body. Without an upper bound, a
        // multi-gigabyte (or, on a 64-bit system, up to ~18 exabyte) `body`
        // would scale this timeout to an effectively infinite hang instead
        // of a bounded one.
        const MAX_UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
        let upload_timeout = MIN_UPLOAD_TIMEOUT
            .max(std::time::Duration::from_secs_f64(
                (body.len() as f64 / (100.0 * 1024.0)) * 2.0,
            ))
            .min(MAX_UPLOAD_TIMEOUT);
        // Redirects disabled specifically for this request (the shared
        // `self.agent`'s own default - 10 - is left alone for every other
        // method here) - `upload.rs`'s SSRF guard checks only the initial
        // URL string returned by Kiln's direct-upload response, so a
        // compromised or misconfigured server could otherwise bypass it
        // entirely by returning a legitimate public URL that redirects to a
        // private/loopback address at the blob-storage level, no DNS
        // involvement required.
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
        send(req.send(body))
    }
}

/// Distinguishes "confirmed different origin" from "couldn't even parse one
/// of the URLs to check" - `raw_post` treats these differently: a genuine
/// origin mismatch still sends the request (unauthenticated, with a
/// warning), but a parse failure means something is structurally wrong with
/// a URL this crate itself should always be able to parse (`base_url_trimmed()`
/// already passed through `config::enforce_secure`, which parses it with
/// this same `url` crate), so it's treated as a hard error instead of
/// silently downgrading to an unauthenticated request.
enum OriginCheck {
    Same,
    Different,
    ParseError,
}

/// `Same` when `a` and `b` share the same scheme, host, and port - used to
/// decide whether it's safe to attach this client's bearer token to a
/// caller-supplied URL. Parses both properly via the `url` crate rather than
/// a string prefix/substring check, which a hostname like
/// `base.starts_with_this.evil.com` could slip past.
fn check_origin(a: &str, b: &str) -> OriginCheck {
    let (Ok(a), Ok(b)) = (url::Url::parse(a), url::Url::parse(b)) else {
        return OriginCheck::ParseError;
    };
    // `port_or_known_default()` returns `None` for a scheme the `url` crate
    // doesn't recognize (i.e. anything but a handful of well-known ones like
    // http/https/ftp) when no explicit port is given - so two URLs using the
    // same unrecognized scheme would otherwise both compare `None == None`
    // as a "port match" and could be treated as same-origin. Requiring both
    // to resolve to `Some` closes that.
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

fn send(result: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> ApiResponse {
    match result {
        Ok(mut response) => {
            let status = response.status().as_u16();
            let text = response.body_mut().read_to_string().unwrap_or_else(|e| {
                eprintln!("Failed to read response body: {e}");
                std::process::exit(1);
            });
            if text.trim().is_empty() {
                return ApiResponse {
                    status,
                    body: Value::Null,
                    json_parse_failed: false,
                };
            }
            match serde_json::from_str(&text) {
                Ok(body) => ApiResponse {
                    status,
                    body,
                    json_parse_failed: false,
                },
                Err(e) => {
                    // A single pass via `char_indices` - `nth(200)` gives
                    // both the byte offset to slice on (so no intermediate
                    // `String` needs collecting from a `Chars` iterator) and,
                    // via `is_some()`, whether the body had more than 200
                    // chars to begin with. Either way this only ever looks at
                    // the first 201 chars regardless of how large the body
                    // is.
                    let (preview, truncated) = match text.char_indices().nth(200) {
                        Some((i, _)) => (&text[..i], "..."),
                        None => (text.as_str(), ""),
                    };
                    // Includes `e` (the actual parse error) - previously
                    // discarded entirely, leaving no diagnostic information
                    // for a developer wondering why e.g. a 422 with an HTML
                    // body from a WAF or reverse proxy shows up as a null body.
                    eprintln!(
                        "Warning: response body was not valid JSON ({e}): {preview}{truncated}"
                    );
                    // `json_parse_failed` set, not the status overwritten to
                    // a synthetic value - `status` stays the real HTTP status
                    // the server sent (a caller checking for a specific code,
                    // e.g. `print_status`'s `403` check, or just displaying
                    // it for diagnostics, still sees the truth). This flag is
                    // what makes `is_success()` correctly treat a 2xx with an
                    // unparseable body as failure (`print_status` would
                    // otherwise print "Overall readiness: 0%", `print_list_
                    // response` would print "null", both with a misleading
                    // zero exit code) - a non-2xx status (a 503 from a load
                    // balancer's HTML maintenance page, a 429 with a
                    // plain-text body) was already correctly "not success"
                    // regardless.
                    ApiResponse {
                        status,
                        body: Value::Null,
                        json_parse_failed: true,
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Prints a JSON:API list response, and a "showing N of TOTAL" trailer when
/// the response carries a paginated meta.total. A failed request exits
/// non-zero with the error body instead of printing it as if it were a
/// successful list, same as print_response.
pub(crate) fn print_list_response(response: &ApiResponse) {
    // `raw_body()`/`body()`, not the private `response.body` field directly -
    // this only compiled before because these functions share a module with
    // `ApiResponse`, silently bypassing the accessor contract those methods
    // exist to enforce (`raw_body()` for "may be a placeholder Null" error
    // display, `body()` for "known good, or None on parse failure" success
    // reads). `is_success()` already guarantees `json_parse_failed == false`
    // on the success path below, so `body()` is infallible there, but using
    // the accessor still keeps this code correct if `ApiResponse` is ever
    // extracted into a different module.
    if !response.is_success() {
        eprintln!("Error {}: {}", response.status, response.error_detail());
        std::process::exit(1);
    }
    let body = response.body().unwrap_or(&Value::Null);
    // `expect()`, not `unwrap_or_default()` - `is_success()` above already
    // guarantees printable output is expected here, so a serialization
    // failure should surface loudly (matching `write()`/`call_write()`'s
    // pattern for the same provably-infallible `serde_json::Value`
    // serialization) rather than silently printing nothing with exit code 0,
    // indistinguishable from a genuinely empty response.
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
    println!(
        "{}",
        serde_json::to_string_pretty(response.body().unwrap_or(&Value::Null))
            .expect("serializing a serde_json::Value always succeeds")
    );
}

/// Areas averaged into the "overall %" - matches useComplianceData.ts's
/// `overallCompliance` (NOT the unused `overallCompliancePercentage` sibling
/// in the same file, which weights differently across all areas with data).
const OVERALL_AREAS: &[&str] = &[
    "employees",
    "policies",
    "account_information",
    "controls",
    "risk_scenarios",
];

/// Order and labels mirror ComplianceProgress.vue's areaLabels map. There is
/// deliberately no "events" row - the UI's "Plan all Events" has no backing
/// area in this endpoint.
const AREA_ORDER: &[(&str, &str)] = &[
    ("account_information", "Company information"),
    ("employees", "People"),
    ("vendors", "Vendors"),
    ("devices", "Add Assets"),
    ("policies", "Review Policies"),
    ("risk_scenarios", "Add & Review Risks"),
    ("controls", "Add & Review Controls"),
];

/// `klaay status` - calls GET /compliance_stats and renders the same numbers
/// the "Road to Readiness" widget shows, computed the same way the frontend
/// does rather than a reinvented formula.
pub(crate) fn print_status(client: &ApiClient, json: bool) {
    // A real `assert!`, not `debug_assert!` - this is a pure compile-time
    // check over two tiny `&[&str]` constants (zero runtime cost either
    // way), so there's no performance reason to compile it away in release
    // builds. Every `OVERALL_AREAS` entry must also have a row in
    // `AREA_ORDER` - if a future edit adds one without the other, that area
    // would silently be folded into the overall percentage without ever
    // appearing in the per-area table below, and the overall % would stop
    // matching the sum of the visible rows with no indication why - exactly
    // the kind of bug a release build (where `debug_assert!` is a no-op)
    // would otherwise ship with silently.
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

    // Borrowed, not `.cloned()` - `data` is only ever read below, and
    // `response` isn't moved or dropped before the loop finishes, so cloning
    // the entire array (potentially large, for a big `compliance_stats`
    // response) would be a wasted allocation.
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
        // `continue`d, not `.unwrap_or_default()` into `""` - unlike a
        // missing `meta` key just above (also `continue`d), a missing or
        // non-string `area` has nowhere legitimate to go: `""` would still
        // get inserted as a real key into `percentages`/`totals` below and
        // rendered as a spurious, blank-labeled row.
        let Some(area) = meta.get("area").and_then(|v| v.as_str()) else {
            continue;
        };
        let area = area.to_string();
        let total = meta.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        // A `HashSet`, not a `Vec` - `compliant_states` is server-controlled,
        // and a duplicate entry (e.g. `["ready", "ready"]`) would otherwise
        // sum the same tally bucket twice below, producing a compliant_count
        // above `total` and a displayed percentage over 100%.
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
        // `.fold` with `saturating_add`, not `.sum()` - these values come
        // directly from the server, and a plain `.sum()` wraps silently on
        // overflow in a release build (or panics in a debug build) rather
        // than saturating.
        //
        // Two more guards beyond the plain saturating add, both because the
        // server controls every value here: (1) a single bucket already
        // larger than `total` (e.g. `{"ready": 999}` against `total: 10`) is
        // corrupt data by definition - no legitimate tally entry can exceed
        // the item count - so it's rejected outright rather than folded in;
        // (2) the running total is capped at `total` after every addition,
        // not just once at the end, so summing several buckets that are each
        // individually under `total` but which together still exceed it
        // (e.g. `{"ready": u64::MAX, "ok": 1}` saturating to `u64::MAX`) is
        // caught immediately rather than relying on the final `clamp` below -
        // that clamp only bounds the *percentage*, and a `compliant_count`
        // that's already saturated to `u64::MAX` would clamp to exactly
        // 100%, the single most misleading value a compliance tool could
        // display.
        let compliant_count: u64 = tally
            .map(|t| {
                compliant_states
                    .iter()
                    .filter_map(|s| t.get(s))
                    .filter_map(|v| v.as_u64())
                    // Warned, not silently dropped - without this, a
                    // rejected bucket (see the comment above on why one
                    // exceeding `total` is corrupt data) contributes 0 to
                    // `compliant_count` with no indication anything was
                    // rejected, so a user sees a plain "0%" indistinguishable
                    // from an area that's genuinely at 0% compliance.
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
                        // Warned, for the same reason as the per-bucket
                        // reject above - silently capping at `total` here
                        // would print a plain 100%, indistinguishable from a
                        // genuinely fully-compliant area, when several
                        // individually-plausible buckets summed past it.
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
            // Clamped, not trusted outright - belt-and-suspenders alongside
            // the per-value reject and running cap above, in case `total`
            // itself is 0 or otherwise degenerate.
            ((compliant_count as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        percentages.insert(area.clone(), pct);
        totals.insert(area, total);
    }

    // Divides by the constant OVERALL_AREAS.len() (5), not by how many of
    // those areas actually came back in the response - this matches
    // useComplianceData.ts's overallCompliance, which makes the same
    // assumption that all 5 areas are always present. If the API ever omits
    // one, this drags the average down rather than erroring - warn so that's
    // visible instead of just looking like a plausible-but-wrong number.
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

    // `{:.0}` rather than `.round() as i64` purely for consistency with the
    // per-area percentages below (both format the same way). `overall` can't
    // actually be NaN today: the divisor is the constant OVERALL_AREAS.len()
    // (5), not the count of areas actually present, so a fully-missing
    // response still yields a well-defined 0.0 / 5.0 = 0.0% here - the
    // `missing_areas` warning above is what makes that case visible, not
    // this formatting choice.
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
