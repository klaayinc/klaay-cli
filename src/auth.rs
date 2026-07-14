use crate::client::{ApiClient, ApiResponse, HttpMethod, ListParams};
use crate::config::Config;
use crate::token_store::{self, StoredToken};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use std::io::{IsTerminal, Write};

/// Decodes a JWT's payload locally without verifying the signature - fine for
/// reading our own token's claims (exp, account_id) since the server verifies
/// signature/expiry on every real request anyway.
fn decode_jwt_payload(token: &str) -> Value {
    let parts: Vec<&str> = token.split('.').collect();
    // `!= 3`, not `< 2` - a well-formed JWT always has exactly 3 dot-
    // separated segments (header, payload, signature). `< 2` would accept a
    // corrupted/truncated token with only 2 segments (e.g. a signature
    // dropped in transit or by a bug elsewhere), silently decoding `parts[1]`
    // as if it were a real payload - if that happens to still deserialize as
    // JSON, the resulting claims (e.g. `account_id`) could be wrong or
    // absent without any indication the token was malformed in the first
    // place.
    if parts.len() != 3 {
        return Value::Null;
    }
    URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}

/// The three credential variants that carry a plaintext secret directly in
/// the /authenticate request body (password, or one of the two SSO
/// providers' verified ID tokens - see authenticate_controller.rb). Split
/// out from `Credentials` (rather than one flat enum with an `Upgrade` arm
/// alongside these) specifically so `build_secret_auth_body` - which only
/// ever handles this subset - can express that as its parameter type. That
/// makes "called with Upgrade" a compile error instead of a `unreachable!()`
/// runtime assertion that a future refactor could silently invalidate.
enum SecretCredentials {
    Password {
        email: zeroize::Zeroizing<String>,
        password: zeroize::Zeroizing<String>,
    },
    Google {
        id_token: zeroize::Zeroizing<String>,
    },
    Microsoft {
        id_token: zeroize::Zeroizing<String>,
    },
}

/// The full set of ways `/authenticate` accepts a request. `Upgrade` is the
/// second call that just picks an account for an already-authenticated
/// bearer token - no credentials to resend, hence it not belonging in
/// `SecretCredentials` (there's no password/id_token to protect here, just
/// the bearer already being upgraded).
enum Credentials {
    Secret(SecretCredentials),
    /// The bearer token lives inside the variant, not as a separate
    /// `Option<&str>` parameter on `post_authenticate` - an upgrade request
    /// is meaningless without one, so this makes that invalid state
    /// unrepresentable instead of relying on every caller to remember it.
    /// `Zeroizing<String>` for the same reason the request-body secrets are:
    /// this bearer token is exactly as sensitive as a password.
    Upgrade {
        bearer: zeroize::Zeroizing<String>,
    },
}

/// Builds the /authenticate request body directly as bytes for any
/// `SecretCredentials` variant - never placing that secret in a
/// `serde_json::Value` at all. An earlier version went through `json!()` and
/// zeroized the resulting `Value::String` after serialization - a real but
/// incomplete improvement, since the secret still existed as an unguarded
/// `Value` copy for the whole `json!()`/`to_vec()` call. Hand-building the
/// exact same wire format for the sensitive field removes that intermediate
/// representation entirely. The non-secret fields (email, account id) still
/// go through `serde_json::to_string` for correct escaping - that's fine,
/// they're not secrets. `Credentials::Upgrade` has no secret in the body
/// itself (its token travels as an `Authorization` header, added by the
/// caller) - it isn't a `SecretCredentials` variant at all, so there's no
/// arm here that could mishandle it.
fn build_secret_auth_body(
    credentials: &SecretCredentials,
    account_id: Option<&str>,
) -> zeroize::Zeroizing<Vec<u8>> {
    // Named constants, not inline string literals directly in the `match` -
    // `field_name` is pushed unescaped into the hand-rolled JSON body below
    // (`json.push_str(field_name)`, not `serde_json::to_string`), so its
    // safety depends on every value being a JSON-special-character-free
    // compile-time literal. Naming them here makes that a property of the
    // three constants themselves, verifiable independently of the `match`,
    // rather than an invariant that would need re-checking by hand if a
    // future `SecretCredentials` variant were added inline.
    const PASSWORD_KEY: &str = "password";
    const GOOGLE_KEY: &str = "google_credentials";
    const MICROSOFT_KEY: &str = "microsoft_credentials";
    let (field_name, secret) = match credentials {
        SecretCredentials::Password { password, .. } => (PASSWORD_KEY, password.as_str()),
        SecretCredentials::Google { id_token } => (GOOGLE_KEY, id_token.as_str()),
        SecretCredentials::Microsoft { id_token } => (MICROSOFT_KEY, id_token.as_str()),
    };
    // `Zeroizing<String>` from the moment it's created, not a plain `String`
    // only zeroized explicitly further down - the explicit
    // `zeroize::Zeroize::zeroize` call below still runs (eagerly, before the
    // capacity assertion), but this closes the narrow window before that
    // point too: an allocation panic in `String::with_capacity` or an
    // `.expect()` panic on one of the *other* fields serialized below would
    // otherwise unwind past the explicit call and drop this as an unzeroized
    // plain `String`.
    let mut secret_json: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
        serde_json::to_string(secret).expect("a string always serializes to JSON"),
    );
    // `Zeroizing<String>`, matching `secret_json` above - the email address
    // is PII, and an unhandled panic anywhere between here and the end of
    // this function would otherwise leave the JSON-encoded email sitting in
    // an unzeroized heap allocation, the same gap this function already
    // takes care to close for the secret itself.
    let email_json: Option<zeroize::Zeroizing<String>> =
        if let SecretCredentials::Password { email, .. } = credentials {
            Some(zeroize::Zeroizing::new(
                serde_json::to_string(email).expect("a string always serializes to JSON"),
            ))
        } else {
            None
        };
    // `Zeroizing<String>`, matching `email_json`/`secret_json` above - an
    // account id isn't as sensitive as a password/email, but this function
    // otherwise treats every JSON-encoded field the same way (see the
    // capacity formula's comment below, which already groups all three
    // together), so leaving this one as a plain `String` was an
    // inconsistency rather than a deliberate distinction.
    let id_json: Option<zeroize::Zeroizing<String>> = account_id.map(|id| {
        zeroize::Zeroizing::new(
            serde_json::to_string(id).expect("a string always serializes to JSON"),
        )
    });

    const PREFIX: &str = r#"{"data":{"type":"authorization","attributes":{"client":"cli""#;
    // Every JSON key below (email, the secret field, account id) uses this
    // same sandwich - `,"` + key + `":` - with the *value* appended
    // separately, already pre-quoted by `serde_json::to_string`. Keeping
    // every key on one shared convention (rather than e.g. baking `"email":`
    // whole into its own prefix constant) is what makes the capacity formula
    // below auditable: every term has the same shape,
    // `KEY_PREFIX.len() + key.len() + KEY_SUFFIX.len() + value.len()`.
    const KEY_PREFIX: &str = ",\"";
    const KEY_SUFFIX: &str = "\":";
    const EMAIL_KEY: &str = "email";
    // `&str`, not `char` - consistent with every other constant in this
    // block, and lets the capacity formula below use `.len()` instead of a
    // hardcoded `+ 1`, so a future change to this constant (e.g. to a
    // multi-byte value) can't silently desync the capacity pre-computation
    // from what's actually pushed - exactly the invariant the `assert!`
    // further down exists to catch.
    const ATTRIBUTES_CLOSE: &str = "}";
    // Unlike the two keys above, this isn't a bare top-level attribute - it's
    // nested three levels into `relationships.account.data.id`, so the
    // literal text carries that whole path rather than just being another
    // KEY_PREFIX/KEY_SUFFIX pair. `id_json` (like `email_json`/`secret_json`
    // above) is a full `serde_json::to_string` output - already wrapped in
    // its own quotes - so it's appended directly after the trailing `:`.
    const RELATIONSHIPS_PREFIX: &str =
        r#","relationships":{"account":{"data":{"type":"account","id":"#;
    const RELATIONSHIPS_SUFFIX: &str = "}}}";
    const TAIL: &str = "}}";

    // Every piece below is computed up front so `json`'s capacity can be
    // reserved exactly once and never needs to grow after the secret is
    // appended - a reallocation past that point would leave the old buffer
    // (still holding the secret's bytes) freed but unzeroed on the heap,
    // which `secret_json`'s own zeroize call below can't reach since it only
    // ever held a copy of that buffer, not the buffer itself.
    let capacity = PREFIX.len()
        + email_json.as_ref().map_or(0, |e| {
            KEY_PREFIX.len() + EMAIL_KEY.len() + KEY_SUFFIX.len() + e.len()
        })
        + KEY_PREFIX.len()
        + field_name.len()
        + KEY_SUFFIX.len()
        + secret_json.len()
        + ATTRIBUTES_CLOSE.len()
        + id_json.as_ref().map_or(0, |i| {
            RELATIONSHIPS_PREFIX.len() + i.len() + RELATIONSHIPS_SUFFIX.len()
        })
        + TAIL.len();

    // `Zeroizing<String>` from creation, not just wrapped at the end - once
    // `secret_json` is pushed in below, this buffer holds the secret's bytes
    // too. `Zeroizing<String>` derefs to `String` so every `push_str` call
    // below is unchanged; this only matters for what happens if a panic
    // unwinds through this function before `into_bytes()` is reached (with a
    // plain `String`, that unwind would drop the secret-bearing buffer
    // without zeroing it).
    let mut json: zeroize::Zeroizing<String> =
        zeroize::Zeroizing::new(String::with_capacity(capacity));
    json.push_str(PREFIX);
    if let Some(email_json) = &email_json {
        json.push_str(KEY_PREFIX);
        json.push_str(EMAIL_KEY);
        json.push_str(KEY_SUFFIX);
        json.push_str(email_json);
    }
    json.push_str(KEY_PREFIX);
    json.push_str(field_name);
    json.push_str(KEY_SUFFIX);
    json.push_str(&secret_json);
    json.push_str(ATTRIBUTES_CLOSE);
    if let Some(id_json) = &id_json {
        json.push_str(RELATIONSHIPS_PREFIX);
        json.push_str(id_json);
        json.push_str(RELATIONSHIPS_SUFFIX);
    }
    json.push_str(TAIL);

    // Cleans up this function's own transient copies - `secret_json` (the
    // reason this call exists at all: see `email_json`'s own doc comment
    // above for the identical PII-in-memory reasoning that applies equally
    // here), and `email_json`/`id_json` alongside it for the same reason,
    // done before the capacity assertion below, not after. Even though this
    // crate doesn't set `panic = "abort"` (so an ordinary panic here would
    // still unwind and run every `Zeroizing`'s own `Drop`), zeroizing
    // explicitly and this early - rather than relying on Drop at all -
    // shrinks the window these still sit in memory unprotected against a
    // kill Drop can never run for (SIGKILL, OOM-kill, power loss), matching
    // this function's existing security model rather than only applying it
    // to one of the three sensitive values built here.
    zeroize::Zeroize::zeroize(&mut secret_json);
    if let Some(mut email_json) = email_json {
        zeroize::Zeroize::zeroize(&mut email_json);
    }
    if let Some(mut id_json) = id_json {
        zeroize::Zeroize::zeroize(&mut id_json);
    }

    // Converted to `Zeroizing<Vec<u8>>` here, immediately after `json` is
    // fully built and *before* the assertion below - not only at the final
    // return. `json` is already `Zeroizing<String>` (see above), so this is
    // about the *container* type, not first-time protection: `into_bytes()`
    // isn't callable directly on `Zeroizing<String>` (it derefs to `&String`/
    // `&mut String`, not an owned `String`), so `std::mem::take` extracts the
    // inner `String` (leaving an empty one zeroized in its place by
    // `Zeroizing`'s own `Drop`) before calling `into_bytes()` on it -
    // `String::into_bytes()` reuses the same buffer (no reallocation), so
    // this costs nothing extra. `.len()` below reads through `Deref`, so no
    // move is needed to check it.
    let bytes: zeroize::Zeroizing<Vec<u8>> =
        zeroize::Zeroizing::new(std::mem::take(&mut *json).into_bytes());

    // `debug_assert!`, not a real `assert!` - by the time this could fire,
    // any reallocation (and the resulting unzeroed old buffer) already
    // happened during the `push_str` calls above; the secret's old backing
    // memory was already freed-but-not-zeroed before this line ever runs,
    // and no assertion here can reach back and zero it retroactively. A
    // release-mode `assert!` would only turn that (already unrecoverable)
    // silent bug into a crashed login with the same already-done damage -
    // it adds detection, not prevention, so it isn't worth crashing a real
    // user's production login over.
    //
    // Not narrowed to `#[cfg(test)]` either, despite that same "release
    // gets zero protection either way" reasoning applying just as much
    // there - `debug_assert!` already compiles out of every real release
    // build (the only place users actually run this), so switching to
    // `#[cfg(test)]` wouldn't change release-build behavior at all; it
    // would only remove this check from an ordinary debug `cargo build`/
    // `cargo run`, a real (if narrower) safety net during local
    // development that a test-only gate doesn't provide. Catches a wrong
    // capacity *formula* (a development-time correctness bug in the
    // hand-computed sum above, in either direction) - `bytes.len() >
    // capacity` specifically is only possible if more bytes were pushed
    // than the buffer was ever asked to reserve, i.e. a reallocation - so
    // the 4 tests in this file's own test module that build a real request
    // body through this function (`password_auth_body_without_account_id_
    // is_valid_json`, `password_auth_body_with_account_id_is_valid_json`,
    // `google_id_token_auth_body_is_valid_json`,
    // `microsoft_id_token_auth_body_is_valid_json`) keep catching a
    // regression here during `cargo test` (which builds with
    // `debug_assertions` on by default), on top of the dev-build coverage
    // above. A second, separate `bytes.len() <= capacity` check isn't
    // needed alongside this: `debug_assert_eq!` already panics on *any*
    // mismatch, so a `<=` check evaluated after it passes would only ever
    // see the case it already confirmed true - dead code that adds no
    // independent protection.
    //
    // Deliberately compared against the pre-computed `capacity` estimate,
    // not `bytes.capacity()` - the latter would reintroduce a real
    // false-positive risk: `with_capacity(n)` is only guaranteed to reserve
    // *at least* `n` bytes, and an allocator that rounds requests up to its
    // own internal size classes (jemalloc and glibc's malloc both do, on
    // some request sizes) could leave `bytes.capacity()` a few bytes above
    // `capacity` with zero reallocation - a benign padding artifact this
    // crate can't assume away across every platform it's distributed to,
    // and one that has no bearing on whether a secret was left unzeroed.
    // Comparing against the fixed `capacity` estimate instead sidesteps that
    // entirely: allocator padding can only ever make `bytes.capacity()`
    // larger than `capacity`, never `bytes.len()`.
    debug_assert_eq!(bytes.len(), capacity, "capacity estimate must be exact");

    // Returned as `Zeroizing<Vec<u8>>` directly (not a plain `Vec<u8>` the
    // caller then wraps) - closes even the small window between this
    // function returning and the caller's own `Zeroizing::new(...)` call,
    // and means every call site (including the 4 test functions below) gets
    // a protected value with no separate wrapping step to remember (see the
    // caveat on `post_authenticate` about `process::exit` paths, which no
    // `Drop` impl - `Zeroizing` included - can protect against).
    bytes
}

/// Builds the /authenticate request body for `Credentials::Upgrade` via the
/// ordinary `serde_json::Value` path - it carries no plaintext secret in the
/// body (the bearer token being upgraded travels as an `Authorization`
/// header instead), so the extra care `build_secret_auth_body` takes doesn't
/// apply here.
fn build_upgrade_auth_body(account_id: Option<&str>) -> zeroize::Zeroizing<Vec<u8>> {
    let attributes = json!({ "client": "cli" });
    let mut data = json!({ "type": "authorization", "attributes": attributes });
    if let Some(id) = account_id {
        data["relationships"] = json!({ "account": { "data": { "type": "account", "id": id } } });
    }
    let body = json!({ "data": data });
    // No plaintext secret in this body today (the bearer token being
    // upgraded travels as an `Authorization` header, not in here) - but
    // returning `Zeroizing<Vec<u8>>` directly, matching
    // `build_secret_auth_body`'s signature, means a future field added here
    // (a CSRF token, a secondary credential) is protected automatically
    // rather than depending on every call site remembering to wrap it.
    zeroize::Zeroizing::new(serde_json::to_vec(&body).expect("body serializes to JSON"))
}

/// POST /authenticate uses plain application/json, not application/vnd.api+json:
/// that content type is only enforced on jsonapi_resources controllers, and
/// AuthenticateController is a hand-rolled ApplicationController subclass.
fn post_authenticate(
    config: &Config,
    credentials: &Credentials,
    account_id: Option<&str>,
) -> ApiResponse {
    let agent = ApiClient::new(config.api_url().to_string(), None);
    // `Zeroizing<Vec<u8>>` (rather than a manual `zeroize::Zeroize::zeroize`
    // call after `raw_post` returns) protects the same set of paths a manual
    // call would, plus one more: a panic unwinding out of this function
    // before reaching a manual call's location would skip it, but `Drop`
    // still runs during unwind. What neither approach protects against is
    // `raw_post`/`send` calling `std::process::exit` on a transport-level
    // failure - that skips *all* destructors unconditionally, `Zeroizing`
    // included, so this is a real, accepted gap rather than something this
    // wrapper closes. The OS reclaims the process's memory at exit either
    // way; see the equivalent rebuttal on the `sso.rs` process::exit/zeroize
    // findings for the fuller reasoning.
    //
    // A second, separate gap beyond `process::exit`: `raw_post` hands
    // `bytes` to ureq, which copies it into its own internal HTTP framing
    // buffer (a plain heap allocation with no `Zeroize` impl). `Zeroizing`
    // here only ever protects this crate's own copy - it has no way to
    // reach into ureq's internals and zero its copy too. This is an
    // accepted limitation of building on a general-purpose HTTP client
    // rather than a purpose-built one; noted here so a future reader
    // doesn't assume `Zeroizing` covers the credential end-to-end once it
    // leaves this function.
    let bytes: zeroize::Zeroizing<Vec<u8>> = match credentials {
        Credentials::Upgrade { .. } => build_upgrade_auth_body(account_id),
        Credentials::Secret(sc) => build_secret_auth_body(sc, account_id),
    };

    // Declared in this outer scope (not built and pushed inside the `if
    // let` below) so `headers` can borrow straight from it as `&str` - now
    // that `raw_post` takes `&[(&str, &str)]`, this is the only copy of the
    // formatted "Bearer ..." value that ever exists, and it's zeroized on
    // drop when this function returns. No unprotected `String` copy is ever
    // pushed into `headers`.
    //
    // Built directly into a pre-allocated `Zeroizing<String>` (`push_str`
    // twice), not `Zeroizing::new(format!(...))` - the latter would produce
    // an ordinary heap-allocated `String` from `format!` first, and only
    // *then* move it into `Zeroizing::new`. `String`'s move itself doesn't
    // copy the heap buffer, so this is normally harmless, but nothing in the
    // language guarantees that: an allocator could in principle relocate the
    // data during the move, leaving the original bytes unzeroed. Same
    // pattern as `build_secret_auth_body`'s capacity-preallocated buffer.
    let auth_value = if let Credentials::Upgrade { bearer } = credentials {
        let mut s = zeroize::Zeroizing::new(String::with_capacity("Bearer ".len() + bearer.len()));
        s.push_str("Bearer ");
        s.push_str(bearer.as_str());
        Some(s)
    } else {
        None
    };
    let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
    if let Some(auth_value) = &auth_value {
        headers.push(("Authorization", auth_value.as_str()));
    }
    agent.raw_post(
        &format!("{}/authenticate", config.api_url().trim_end_matches('/')),
        &headers,
        &bytes,
    )
}

fn extract_token(body: &Value) -> Option<&str> {
    body.get("data")?.get("attributes")?.get("token")?.as_str()
}

/// Extracts the token or exits with a clear message - a 201 response missing
/// a token would otherwise be a confusing panic deep in login logic.
/// Returns `Zeroizing<String>` - this is a bearer credential exactly as
/// sensitive as a password, and it's the only source for both the
/// initial/final stored token and (for a multi-account login)
/// `Credentials::Upgrade`'s bearer, so protecting it at the point of
/// extraction covers every downstream copy instead of leaving the original
/// as a plain, unprotected `String` that a later `Zeroizing::new(...)`
/// wrapper only ever covered for a clone taken from it.
fn require_token(body: &Value, context: &str) -> zeroize::Zeroizing<String> {
    let token = extract_token(body).unwrap_or_else(|| {
        // Only the `errors` key, not the whole body - a 201 `/authenticate`
        // response missing its `token` is already an unexpected shape, but
        // the full body can still carry PII in its `included` array (e.g.
        // the `users` resource `extract_email` reads from) that has no
        // business landing in stderr/CI logs/terminal scrollback just
        // because this diagnostic needs *something* to show the user.
        let detail = body
            .get("errors")
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .unwrap_or_else(|| "(no errors key in response)".to_string());
        eprintln!("Login succeeded but the response didn't include a token ({context}): {detail}");
        std::process::exit(1);
    });
    // `extract_token` returns a borrow into `body` rather than its own
    // owned `String` (which was previously allocated only to be moved into
    // this `Zeroizing::new(...)` call anyway) - the single allocation this
    // function needs happens directly here, as part of constructing the
    // protected value, rather than as a separate unprotected intermediate.
    zeroize::Zeroizing::new(token.to_string())
}

/// `-> !` and the `_and_exit` suffix both make the process::exit an explicit
/// part of the signature, not a surprise a caller discovers only by reading
/// the body - a name like `print_login_error` alone reads as "just prints,"
/// which is misleading for a function that never returns.
fn print_login_error_and_exit(status: u16, detail: &str) -> ! {
    eprintln!("Login failed ({status}): {detail}");
    std::process::exit(1);
}

/// Prompts the developer to choose an account from the list GET /accounts
/// returned, or - if stdin isn't a TTY - tells them to pass --account with
/// the valid ids so scripted/non-interactive use fails clearly, not silently.
fn choose_account(accounts: &[Value]) -> String {
    if accounts.is_empty() {
        eprintln!("You're signed in but haven't finished setting up a Klaay workspace yet.");
        std::process::exit(1);
    }

    if accounts.len() == 1 {
        return accounts[0]
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                eprintln!("Account is missing an 'id' field in the API response.");
                std::process::exit(1);
            })
            .to_string();
    }

    // Both the list and its actionable follow-up ("Run again with
    // --account...") go to stderr - this is an interactive prompt, not data
    // output, and printing the list to stdout while the instruction goes to
    // stderr would separate them for anything that captures the two streams
    // independently (e.g. `output=$(klaay login)` in a script or CI).
    eprintln!("You belong to multiple accounts:");
    for (i, account) in accounts.iter().enumerate() {
        let id = account.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let name = account
            .get("attributes")
            .and_then(|a| a.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("(unnamed)");
        eprintln!("  {}) {}  (id {})", i + 1, name, id);
    }

    if !std::io::stdin().is_terminal() {
        eprintln!("Run again with --account <id>, using one of the ids listed above.");
        std::process::exit(1);
    }

    // Retries on an invalid selection rather than exiting outright - the
    // developer already authenticated with real credentials to get here, so
    // making a fat-fingered number entry cost a full re-login was needless
    // friction. Bounded (rather than an unconditional loop) so a TTY session
    // fed bad input indefinitely (e.g. a script driving stdin) can't spin
    // forever - the non-TTY path above already exits immediately instead of
    // ever reaching this loop.
    const MAX_SELECTION_ATTEMPTS: u32 = 5;
    let mut attempts = 0;
    // A single guard at the top of the loop, checked before any input is
    // read - not one copy inside the parse-failure arm and a second inside
    // the out-of-range arm below. Two separate copies of the same cap is an
    // easy invariant to break: a future failure mode added to this loop
    // could forget its own copy and make the loop unbounded for that one
    // path. A single top-of-loop check makes the retry limit apply
    // uniformly no matter how many ways there are to fail a single
    // iteration.
    // Allocated once outside the loop, not `String::new()` inside it -
    // `read_line` appends rather than replacing, so `.clear()` at the top of
    // each iteration reuses the same buffer instead of a fresh heap
    // allocation every retry.
    let mut input = String::new();
    let chosen = loop {
        if attempts >= MAX_SELECTION_ATTEMPTS {
            eprintln!("Too many invalid selections.");
            std::process::exit(1);
        }
        attempts += 1;
        // stderr, not stdout - the account list and the `--account`
        // instruction printed above both already go to stderr, so a caller
        // capturing stdout (e.g. `output=$(klaay login)`) would otherwise see
        // this prompt with no visible context for what it's asking.
        eprint!("Select an account [1-{}]: ", accounts.len());
        std::io::stderr().flush().ok();
        input.clear();
        let bytes = std::io::stdin().read_line(&mut input).unwrap_or_else(|e| {
            eprintln!("Could not read your selection: {e}");
            std::process::exit(1);
        });
        if bytes == 0 {
            eprintln!("\nNo input received.");
            std::process::exit(1);
        }
        // Matched explicitly rather than `.unwrap_or(0)` - that sentinel
        // conflated "typed something non-numeric" with "typed the number 0"
        // into the same fallback value, which also happened to give a
        // misleading "Invalid selection" message for non-numeric input (the
        // real problem was that it didn't parse as a number at all) and
        // would silently stop being a safe sentinel if the valid range ever
        // started at 0.
        let choice: usize = match input.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("Please enter a number between 1 and {}.", accounts.len());
                continue;
            }
        };
        // `checked_sub(1)` rather than `choice < 1 || choice > len` followed
        // by a separate `choice - 1` index - the two checks and the
        // subtraction are two different places that both have to agree
        // `choice` is nonzero, rather than one self-contained expression
        // that can't underflow no matter how this code is refactored later.
        match choice.checked_sub(1).filter(|&i| i < accounts.len()) {
            Some(idx) => break &accounts[idx],
            None => {
                eprintln!(
                    "Invalid selection - enter a number between 1 and {}.",
                    accounts.len()
                );
            }
        }
    };
    chosen
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            eprintln!("Selected account is missing an 'id' field in the API response.");
            std::process::exit(1);
        })
        .to_string()
}

fn extract_email(body: &Value) -> Option<String> {
    body.get("included")?
        .as_array()?
        .iter()
        .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("users"))?
        .get("attributes")?
        .get("email")?
        .as_str()
        .map(|s| s.to_string())
}

pub(crate) fn login(
    config: &Config,
    email: Option<zeroize::Zeroizing<String>>,
    password: Option<zeroize::Zeroizing<String>>,
    account: Option<String>,
) {
    // Printed before any prompt (including the email prompt below) - a user
    // who passed --password but not --email would otherwise see the email
    // prompt, type their email, and only then see the security warning
    // about the password they'd already supplied via the command line.
    if password.is_some() {
        eprintln!(
            "Warning: --password can leak into shell history, `ps` output, or audit logs - prefer the interactive prompt."
        );
    }
    // `Zeroizing<String>`, matching `password` below - the email address is
    // PII, and `build_secret_auth_body` already treats its JSON-encoded form
    // as sensitive enough to zeroize; wrapping the source string the same
    // way closes the gap where the underlying `String` itself (as opposed
    // to just its serialized copy) was never cleared from memory on drop.
    let email = email.unwrap_or_else(|| zeroize::Zeroizing::new(prompt_visible("Email: ")));
    // Checked after resolving from *either* source (the interactive prompt
    // or the `--email` flag) - the previous version only checked the
    // prompted value, so `--email ""` would sail through unvalidated,
    // reaching the server as-is and producing a confusing 422 instead of a
    // clear client-side message.
    if email.is_empty() {
        eprintln!("Email cannot be empty.");
        std::process::exit(1);
    }
    let password = password.unwrap_or_else(|| {
        zeroize::Zeroizing::new(
            rpassword::prompt_password("Password: ").unwrap_or_else(|e| {
                eprintln!("Could not read password: {e}");
                std::process::exit(1);
            }),
        )
    });
    // Same reasoning as the email check above, covering both `--password`
    // and the interactive prompt.
    if password.is_empty() {
        eprintln!("Password cannot be empty.");
        std::process::exit(1);
    }
    login_with_credentials(
        config,
        Credentials::Secret(SecretCredentials::Password { email, password }),
        account,
    );
}

/// The two SSO providers `sso.rs` can produce an id token for. An enum here
/// (rather than `login_with_id_token` taking a raw `&str`, matched against
/// literal `"google"`/`"microsoft"`) makes a typo at a call site a compile
/// error instead of a `process::exit` at runtime - `SecretCredentials`
/// already expresses these same two variants, this just gives the choice
/// between them its own type before the id token is attached.
pub(crate) enum SsoProvider {
    Google,
    Microsoft,
}

pub(crate) fn login_with_id_token(
    config: &Config,
    provider: SsoProvider,
    id_token: zeroize::Zeroizing<String>,
    account: Option<String>,
) {
    let credentials = match provider {
        SsoProvider::Google => Credentials::Secret(SecretCredentials::Google { id_token }),
        SsoProvider::Microsoft => Credentials::Secret(SecretCredentials::Microsoft { id_token }),
    };
    login_with_credentials(config, credentials, account);
}

fn login_with_credentials(config: &Config, credentials: Credentials, account: Option<String>) {
    let response = post_authenticate(config, &credentials, account.as_deref());
    // `is_success()` (which also accounts for an unparseable 2xx body), not
    // a raw `status != 201` check - the latter would fall through to
    // `require_token` on a 201 response whose body failed to parse, since
    // that comparison has no way to see `json_parse_failed`.
    if !response.is_success() {
        print_login_error_and_exit(response.status, &response.error_detail());
    }
    let body = response.body().unwrap_or_else(|| {
        eprintln!(
            "Login succeeded ({}) but the response body wasn't valid JSON.",
            response.status
        );
        std::process::exit(1);
    });
    let first_token = require_token(body, "login");
    let claims = decode_jwt_payload(&first_token);
    // `as_u64`, not `as_i64` - account ids are never negative, and `as_i64`
    // would silently return `None` for a JSON number above `i64::MAX`
    // (Kiln's `account&.id` is a Ruby Integer, arbitrary precision, so a very
    // large id is at least theoretically possible), sending a single-account
    // user down the multi-account upgrade path unnecessarily.
    let account_id = claims.get("account_id").and_then(|v| v.as_u64());
    // Warning deferred until after both branches below have had a chance to
    // set `email` - the multi-account path (no `account_id`/`account` given)
    // re-fetches it from the upgrade response, which can succeed even when
    // this first response didn't carry one. Warning here unconditionally
    // would falsely tell every multi-account user their email couldn't be
    // determined, even when the upgrade response goes on to supply it.
    let mut email: Option<String> = extract_email(body);

    let (final_token, account_name, resolved_account_id) = if account_id.is_some()
        || account.is_some()
    {
        // Either already resolved to exactly one account, or the caller told
        // us which one upfront - nothing more to do.
        let organization = body
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("organization"))
            .and_then(|v| v.as_str());
        let claim_id = account_id.map(|n| n.to_string());
        // If the user explicitly passed --account, make sure it's what
        // the server actually resolved - the JWT claim wins (it's what
        // the token is actually scoped to), but silently substituting a
        // different account than the one requested deserves a warning,
        // not silence. Parses `requested` as an integer before comparing
        // (rather than comparing `claim`'s stringified i64 to the raw
        // user-supplied string) so a non-canonical form the user typed
        // (e.g. a leading-zero-padded id) doesn't produce a false-mismatch
        // warning against an otherwise-matching account.
        match (&claim_id, &account) {
            (Some(claim), Some(requested)) => {
                // `u64`, not `i64` - `claim_id` above comes from `account_id`,
                // which is extracted via `as_u64()` specifically to handle ids
                // above `i64::MAX`. Normalizing the user-supplied `--account`
                // value through `i64` instead would make this comparison always
                // fail for such an id (`parse::<i64>()` returns `None`, so
                // `requested_normalized` is `None`, and `Some(claim) != None` is
                // always true), producing a false-positive mismatch warning on
                // every large-but-valid account id.
                //
                // Only compared when `requested` actually parses - if it
                // doesn't (a UUID, a slug, or any other non-numeric value the
                // user passed to `--account`), there's nothing to normalize
                // against, so `requested_normalized` being `None` must not be
                // treated as "mismatch" the way comparing against a bare
                // `None` would: that fired unconditionally for every
                // non-numeric `--account`, even when the server accepted and
                // resolved that exact value correctly.
                let requested_normalized = requested.parse::<u64>().ok().map(|n| n.to_string());
                if let Some(normalized) = &requested_normalized {
                    if claim != normalized {
                        eprintln!(
                            "Warning: --account {requested} was specified, but the server resolved account {claim}."
                        );
                    }
                }
            }
            // The token doesn't carry an `account_id` claim to confirm
            // against at all - previously silent, even though the user
            // explicitly asked for a specific account and there's no way to
            // tell from this response alone whether the server actually
            // honored that request.
            (None, Some(requested)) => {
                eprintln!(
                    "Warning: --account {requested} was specified, but the token does not include an account_id claim to confirm the resolved account."
                );
            }
            _ => {}
        }
        (
            first_token,
            organization.map(|s| s.to_string()),
            // Prefer the account_id claim, but fall back to the
            // caller-supplied --account: if it got this far the server
            // already accepted and resolved it, so a missing claim just
            // means the JWT didn't embed it - not that no account id is
            // known.
            // `account` isn't used again in this branch after this point, so
            // moving it directly (rather than `.clone()`) avoids an
            // unnecessary allocation.
            claim_id.or(account),
        )
    } else {
        // Multi-account user with no --account given: discover the real
        // candidates via GET /accounts (works even with this accountless
        // token - see Context in the plan for why), then upgrade the token.
        // `first_token` is already `Zeroizing<String>` (it's still needed
        // below as `Credentials::Upgrade`'s bearer), so `.clone()` here
        // produces another `Zeroizing<String>` that's cleared when the
        // probe client drops - no extra wrapping needed.
        let probe = ApiClient::new(config.api_url().to_string(), Some(first_token.clone()));
        let accounts_response = probe.list("accounts", &ListParams::default());
        if !accounts_response.is_success() {
            eprintln!(
                "Could not list accounts: {}",
                accounts_response.error_detail()
            );
            std::process::exit(1);
        }
        // `None` here (missing/unparseable body, or a `data` key that isn't
        // an array) is a response-parsing failure, not "this account
        // genuinely has zero accounts" - collapsing both into
        // `.unwrap_or_default()` meant a malformed response landed on
        // `choose_account(&[])`'s "haven't finished setting up a workspace
        // yet" message, which implies an onboarding problem when the real
        // issue is that this API response couldn't be understood at all.
        let accounts: Vec<Value> = match accounts_response
            .body()
            .and_then(|b| b.get("data"))
            .and_then(|d| d.as_array())
            .cloned()
        {
            Some(accounts) => accounts,
            None => {
                eprintln!("Could not parse the accounts list from the API response.");
                std::process::exit(1);
            }
        };
        let chosen_id = choose_account(&accounts);

        let response = post_authenticate(
            config,
            &Credentials::Upgrade {
                bearer: first_token,
            },
            Some(&chosen_id),
        );
        if !response.is_success() {
            print_login_error_and_exit(response.status, &response.error_detail());
        }
        let body = response.body().unwrap_or_else(|| {
            eprintln!(
                "Account upgrade succeeded ({}) but the response body wasn't valid JSON.",
                response.status
            );
            std::process::exit(1);
        });
        let token = require_token(body, "account upgrade");
        if let Some(e) = extract_email(body) {
            email = Some(e);
        }
        let organization = body
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("organization"))
            .and_then(|v| v.as_str());
        (token, organization.map(|s| s.to_string()), Some(chosen_id))
    };
    if email.is_none() {
        eprintln!("Warning: could not determine the account email from the login response.");
    }

    let final_claims = decode_jwt_payload(&final_token);
    let exp = final_claims.get("exp").and_then(|v| v.as_i64());
    let email_display = email.as_deref().unwrap_or("(unknown email)");

    match (account_name, exp) {
        (Some(name), Some(exp)) => println!(
            "Logged in as {email_display} (account: {name})\nToken stored (expires {})",
            format_timestamp(exp)
        ),
        (Some(name), None) => println!("Logged in as {email_display} (account: {name})"),
        (None, Some(exp)) => println!(
            "Logged in as {email_display}\nToken stored (expires {})",
            format_timestamp(exp)
        ),
        (None, None) => println!("Logged in as {email_display}"),
    }

    if let Err(e) = token_store::save(&StoredToken {
        // Already Zeroizing<String> from require_token (both branches above
        // produce it directly - no separate wrap needed here anymore).
        token: final_token,
        api_url: config.api_url().to_string(),
        account_id: resolved_account_id,
        email,
    }) {
        // `CorruptedFile` gets its own message rather than the generic one
        // below - the underlying credentials file is intact but unreadable,
        // and (per `save_to_file`'s own reasoning) was deliberately left
        // untouched rather than auto-overwritten, so the user has a real
        // action available (fix or delete the file by hand) that the
        // generic message doesn't mention.
        match e {
            token_store::SaveTokenError::CorruptedFile(detail) => {
                eprintln!(
                    "Warning: logged in, but your existing credentials file appears corrupted, so the new token could not be stored there: {detail}"
                );
                eprintln!(
                    "Fix or remove the file it describes by hand, then run `klaay login` again."
                );
            }
            token_store::SaveTokenError::Other(detail) => {
                eprintln!("Warning: logged in, but the token could not be stored: {detail}");
                eprintln!("You'll need to log in again for your next command.");
            }
        }
    }
}

// Named to make the echo-on behavior explicit at every call site (paired
// with `rpassword::prompt_password`'s echo-off naming for the sensitive
// case) - only ever called for the non-sensitive email field today, but a
// generic `prompt` name invites a future caller to reuse it for a password
// or other secret, which would then echo it to the terminal.
fn prompt_visible(label: &str) -> String {
    // stderr, not stdout - matches `choose_account`'s interactive prompts, so
    // a caller capturing stdout (e.g. `output=$(klaay login)`) still sees
    // every prompt rather than just some of them.
    eprint!("{label}");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    let bytes = std::io::stdin().read_line(&mut input).unwrap_or_else(|e| {
        eprintln!("Could not read input: {e}");
        std::process::exit(1);
    });
    if bytes == 0 {
        eprintln!("\nNo input received.");
        std::process::exit(1);
    }
    input.trim().to_string()
}

fn format_timestamp(unix_ts: i64) -> String {
    // Minimal formatting without pulling in a date/time crate - good enough
    // for a human-readable "when does this expire" hint.
    let Ok(since_epoch) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        // System clock set before 1970 - too broken to compute a meaningful
        // delta; degrade gracefully rather than panicking in this
        // user-facing login/whoami message path.
        return "(unknown)".to_string();
    };
    // `as i64` would silently wrap to a large negative number once Unix
    // timestamps exceed i64::MAX (the year 2262) - explicit and degrades the
    // same way the pre-1970 case above does, rather than producing a
    // nonsensical "days ago"/"in N days" value.
    let Ok(now) = i64::try_from(since_epoch.as_secs()) else {
        return "(unknown)".to_string();
    };
    // Checks the sign of the raw seconds-level difference, not of `days`
    // itself - integer division truncates toward zero, so a token that
    // expired e.g. 1 hour ago has `diff == -3600`, and `-3600 / 86400 == 0`
    // in Rust. Branching on `days >= 0` instead of `diff >= 0` would print
    // "in 0 days" (implying the token is still valid) for anything expired
    // less than 24 hours ago, rather than "0 days ago (expired)".
    let diff = unix_ts.saturating_sub(now);
    // `checked_abs`, not `saturating_abs` - `i64::MIN.saturating_abs()`
    // returns `i64::MAX` (there's no valid positive i64 representation of
    // `-i64::MIN`), which is "saturating" in name only: it produces a
    // nonsensical multi-trillion-day value instead of a clear fallback.
    // `unix_ts` comes from a locally-decoded (signature-unverified) JWT
    // claim, so a corrupted or adversarial token really can produce
    // `diff == i64::MIN` here.
    let Some(abs_diff) = diff.checked_abs() else {
        return "(unknown)".to_string();
    };
    let days = abs_diff / 86400;
    if diff >= 0 {
        if days == 0 {
            // Reports hours/minutes instead of "in 0 days" for anything
            // expiring within the next 24 hours - "in 0 days" reads as
            // "still safely valid" when the token could actually expire in
            // the next few minutes. `diff == abs_diff` here (`diff >= 0`),
            // so this is the same magnitude the expired branch below
            // computes from `abs_diff` directly.
            // Safe: this branch is `diff >= 0`, so the conversion is
            // lossless, not wrapping.
            match sub_day_magnitude(diff as u64) {
                SubDayMagnitude::Hours(hours) => format!("in {hours} hours"),
                SubDayMagnitude::Minutes(minutes) => format!("in {minutes} minutes"),
                SubDayMagnitude::UnderMinute => "expires in less than a minute".to_string(),
            }
        } else {
            format!("in {days} days")
        }
    } else if days == 0 {
        // Same reasoning as the not-yet-expired branch above: a token that
        // expired 90 minutes ago should say so, not "0 days ago (expired)".
        // Safe: `abs_diff` comes from `checked_abs()`, always non-negative.
        match sub_day_magnitude(abs_diff as u64) {
            SubDayMagnitude::Hours(hours) => format!("{hours} hours ago (expired)"),
            SubDayMagnitude::Minutes(minutes) => format!("{minutes} minutes ago (expired)"),
            // "0 minutes ago (expired)" reads as ambiguous - it looks like
            // the token might have *just barely* expired or could still be
            // valid, when really it's been anywhere up to 59 seconds.
            // Distinct wording removes that ambiguity.
            SubDayMagnitude::UnderMinute => "less than a minute ago (expired)".to_string(),
        }
    } else {
        format!("{days} days ago (expired)")
    }
}

/// Shared by both branches of `format_timestamp` - the magnitude
/// computation (and the "0 of the coarser unit reads as still/just barely
/// valid" reasoning behind picking a finer one) is identical whether the
/// token is not-yet-expired or already-expired; only the surrounding
/// sentence differs, which stays at each call site.
enum SubDayMagnitude {
    // `u64`, not `i64` - every caller only ever passes `diff` (already
    // checked `>= 0` at its call site) or `abs_diff` (the result of
    // `checked_abs()`), so this value is always non-negative in practice.
    // An unsigned type makes that invariant structural (visible at every
    // `format!` call site rendering it) instead of an implicit fact about
    // the two call sites that a future caller could violate silently.
    Hours(u64),
    Minutes(u64),
    UnderMinute,
}

// Takes `u64`, not `i64` - both call sites already hold a non-negative value
// (see the enum's own doc comment above) and cast at the call site, where the
// guard that makes the cast safe is immediately visible. Taking `i64` here
// would require a hidden `as u64` inside this function with no visible
// guarantee it's non-negative, undermining the very invariant the enum's
// unsigned payload exists to make structural.
fn sub_day_magnitude(abs_seconds: u64) -> SubDayMagnitude {
    let hours = abs_seconds / 3600;
    if hours != 0 {
        return SubDayMagnitude::Hours(hours);
    }
    // Anything expiring/expired within the next/last hour would otherwise
    // report "0 hours", which reads just as falsely reassuring/ambiguous as
    // "0 days" did one level up.
    let minutes = abs_seconds / 60;
    if minutes != 0 {
        SubDayMagnitude::Minutes(minutes)
    } else {
        SubDayMagnitude::UnderMinute
    }
}

pub(crate) fn whoami(config: &Config) {
    let stored = require_login(config);
    // A real Zeroizing clone (not a plain-String .to_string() copy) - stored
    // is still needed below for decode_jwt_payload, so the token can't be
    // moved outright the way authenticated_client's identical construction
    // does in main.rs.
    let client = ApiClient::new(config.api_url().to_string(), Some(stored.token.clone()));
    let response = client.call(HttpMethod::Get, "/me", None);
    if !response.is_success() {
        eprintln!(
            "Session is no longer valid ({}): {}",
            response.status,
            response.error_detail()
        );
        eprintln!("Run `klaay login` again.");
        std::process::exit(1);
    }

    let claims = decode_jwt_payload(&stored.token);
    let exp = claims.get("exp").and_then(|v| v.as_i64());
    let email = stored.email.as_deref().unwrap_or("(unknown email)");
    let account = stored.account_id.as_deref().unwrap_or("(none)");
    match exp {
        Some(exp) => println!(
            "{email}  account={account}  expires {}",
            format_timestamp(exp)
        ),
        None => println!("{email}  account={account}"),
    }
}

pub(crate) fn logout(config: &Config) {
    match token_store::delete(config.api_url()) {
        Ok(true) => println!("Logged out (credentials removed)"),
        // Nothing was actually stored for this api_url in either the
        // keychain or the file fallback - printing "Logged out" here would
        // be misleading, since nothing was removed.
        Ok(false) => println!("Not logged in."),
        Err(e) => {
            eprintln!("Warning: logout may be incomplete: {e}");
            eprintln!("Your credentials might still be present.");
        }
    }
}

/// Loads the stored token or exits with a clear message - every command other
/// than login/logout needs this.
pub(crate) fn require_login(config: &Config) -> StoredToken {
    let mut stored = match token_store::load(config.api_url()) {
        Some(stored) => stored,
        None => {
            eprintln!("Not logged in. Run `klaay login` first.");
            std::process::exit(1);
        }
    };
    // Validated here (once, at the point we own `stored`), not on every
    // outgoing request inside `client.rs`'s `bearer()` - that call only ever
    // sees a `&self` borrow, so on invalid input it could only
    // `std::process::exit` past a *reference*, which does nothing to
    // zeroize the real backing buffer (a suggested fix that clones-then-
    // zeroizes the clone has the same problem: it protects a throwaway copy,
    // not the original). Here we own `stored.token` outright, so an explicit
    // zeroize actually clears the real bytes before we exit, regardless of
    // whether `Drop` gets to run afterward. The token is only ever read (not
    // mutated) after this point, so checking once here covers every later
    // `bearer()` call too - tightened to the actual JWT character set
    // (base64url alphanumerics, `-`, `_`, and the `.` separators between
    // header/payload/signature) rather than the much broader
    // `is_ascii_graphic()` (all of 0x21-0x7E). A token containing something
    // outside that set is corrupted either way, but the narrower check also
    // closes a real gap: `is_ascii_graphic()` still accepts characters like
    // `"`, `#`, `[`, `\`, or `,` that are illegal in a JWT but would reach
    // ureq's header API verbatim inside the `Authorization` value if this
    // check were ever bypassed or weakened.
    // The character-set check alone lets a corrupted value like "abc.def"
    // (2 segments) through unchanged - it's built entirely from legal JWT
    // characters, just not enough of them in the right shape. Checking the
    // structural 3-segment requirement (header.payload.signature) alongside
    // it means a malformed stored token is caught here, with a clear "run
    // `klaay login` again" message and its bytes zeroized, instead of being
    // forwarded to the server as a `Bearer` header and surfacing only as a
    // confusing auth failure once the server rejects it.
    //
    // `count() != 3` alone still passes a value like "..sig" or "header.."
    // through unchanged - splitting on '.' produces exactly 3 substrings for
    // those too, just with one or two of them empty. Rejecting any empty
    // segment closes that gap without weakening the check above.
    // Scoped into its own block, rather than sharing the enclosing scope
    // with the `zeroize::Zeroize::zeroize(&mut stored)` call below -
    // `token_parts` borrows `stored.token`, and NLL already proves that
    // borrow dead before the mutable borrow zeroize takes (it's last read
    // in this very condition), so this block doesn't change what compiles.
    // What it does change: a future diagnostic (e.g. an `eprintln!` printing
    // a `token_parts` element) added inside the `if` body below could no
    // longer accidentally read from `stored.token` after it's been zeroized
    // - the borrow's lifetime is now bounded by this block, not by "wherever
    // `token_parts` happens to last be read", so the safe ordering is
    // enforced structurally instead of resting on NLL reasoning a future
    // edit could quietly invalidate.
    let token_is_valid = {
        let token_parts: Vec<&str> = stored.token.split('.').collect();
        stored
            .token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && token_parts.len() == 3
            && token_parts.iter().all(|p| !p.is_empty())
    };
    if !token_is_valid {
        eprintln!("Stored token is invalid - run `klaay login` again.");
        // Zeroizes the whole struct (it derives `Zeroize`), not just
        // `stored.token` - `api_url`/`account_id`/`email` aren't secrets on
        // the level `token` is, but there's no cost to clearing them too,
        // and it means a future field added to `StoredToken` is covered
        // automatically instead of silently falling outside this exit path.
        zeroize::Zeroize::zeroize(&mut stored);
        std::process::exit(1);
    }
    stored
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the hand-rolled JSON construction in `build_secret_auth_body`
    /// against a mismatched brace or bad escaping - it's built with manual
    /// `push_str` calls specifically to avoid ever putting the secret
    /// through `serde_json::Value`, so it doesn't get the usual "the
    /// serializer can't produce invalid JSON" guarantee for free.
    #[test]
    fn password_auth_body_without_account_id_is_valid_json() {
        let credentials = SecretCredentials::Password {
            email: zeroize::Zeroizing::new("dev@customer.com".to_string()),
            password: zeroize::Zeroizing::new("hunter2".to_string()),
        };
        let bytes = build_secret_auth_body(&credentials, None);
        let parsed: Value = serde_json::from_slice(&bytes).expect("must be valid JSON");
        assert_eq!(
            parsed["data"]["attributes"]["email"].as_str(),
            Some("dev@customer.com")
        );
        assert_eq!(
            parsed["data"]["attributes"]["password"].as_str(),
            Some("hunter2")
        );
        assert_eq!(parsed["data"]["attributes"]["client"].as_str(), Some("cli"));
        assert_eq!(parsed["data"]["type"].as_str(), Some("authorization"));
        assert!(parsed["data"].get("relationships").is_none());
    }

    #[test]
    fn password_auth_body_with_account_id_is_valid_json() {
        let credentials = SecretCredentials::Password {
            email: zeroize::Zeroizing::new("dev@customer.com".to_string()),
            password: zeroize::Zeroizing::new("p@ss\"w/ord\n".to_string()),
        };
        let bytes = build_secret_auth_body(&credentials, Some("42"));
        let parsed: Value = serde_json::from_slice(&bytes).expect("must be valid JSON");
        assert_eq!(
            parsed["data"]["attributes"]["password"].as_str(),
            Some("p@ss\"w/ord\n")
        );
        assert_eq!(
            parsed["data"]["relationships"]["account"]["data"]["type"].as_str(),
            Some("account")
        );
        assert_eq!(
            parsed["data"]["relationships"]["account"]["data"]["id"].as_str(),
            Some("42")
        );
    }

    #[test]
    fn google_id_token_auth_body_is_valid_json() {
        let credentials = SecretCredentials::Google {
            id_token: zeroize::Zeroizing::new("some.jwt.token".to_string()),
        };
        let bytes = build_secret_auth_body(&credentials, None);
        let parsed: Value = serde_json::from_slice(&bytes).expect("must be valid JSON");
        assert_eq!(
            parsed["data"]["attributes"]["google_credentials"].as_str(),
            Some("some.jwt.token")
        );
        assert!(parsed["data"]["attributes"].get("email").is_none());
    }

    #[test]
    fn microsoft_id_token_auth_body_is_valid_json() {
        let credentials = SecretCredentials::Microsoft {
            id_token: zeroize::Zeroizing::new("some.jwt.token".to_string()),
        };
        let bytes = build_secret_auth_body(&credentials, Some("7"));
        let parsed: Value = serde_json::from_slice(&bytes).expect("must be valid JSON");
        assert_eq!(
            parsed["data"]["attributes"]["microsoft_credentials"].as_str(),
            Some("some.jwt.token")
        );
        assert_eq!(
            parsed["data"]["relationships"]["account"]["data"]["id"].as_str(),
            Some("7")
        );
    }
}
