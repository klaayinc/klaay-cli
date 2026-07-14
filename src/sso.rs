use crate::auth;
use crate::config::Config;
use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenType,
};
use oauth2::{
    AuthUrl, AuthorizationCode, Client, ClientId, CsrfToken, DeviceAuthorizationUrl,
    EndpointNotSet, ExtraTokenFields, HttpRequest, HttpResponse, PkceCodeChallenge, RedirectUrl,
    Scope, StandardDeviceAuthorizationResponse, StandardRevocableToken, StandardTokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use url::form_urlencoded;

// Both providers' web-application OAuth clients (the ones the browser SPA
// uses) can't do a CLI-style redirect - Google/Microsoft don't allow a
// "Web application" client to redirect to an arbitrary localhost port the
// way an installed/native app client can. Both flows here depend on
// separate, CLI-specific OAuth client registrations that don't exist yet -
// see the plan's "Blocking prerequisite for SSO login" note. Until those
// exist, these commands fail with a clear message rather than a confusing
// network error.

// `Zeroizing<String>` (not plain `String`) so the credential is zeroized
// from the moment it's deserialized, covering the *original* allocation
// inside `OidcTokenResponse` - not just a clone taken from it later. The
// `zeroize` crate's "serde" feature (already enabled in Cargo.toml) makes
// `Zeroizing<String>` transparently (de)serializable, so this needs no
// other changes to work with oauth2's token-response deserialization.
#[derive(Clone, Deserialize)]
struct IdTokenFields {
    id_token: Option<zeroize::Zeroizing<String>>,
}
impl ExtraTokenFields for IdTokenFields {}

/// `Serialize` is required by the `ExtraTokenFields` trait bound itself
/// (confirmed directly against the installed oauth2 5.0.0 crate source:
/// `pub trait ExtraTokenFields: DeserializeOwned + Debug + Serialize {}`),
/// so it can't simply be dropped from this struct. Hand-written rather than
/// derived, for the same reason as the `Debug` impl below: a derived
/// `Serialize` would emit the raw id_token JWT in full if `OidcTokenResponse`
/// (which embeds this) is ever serialized - for debug logging, a test
/// snapshot, or persistence. No code path does that today, but the trait
/// bound means the capability always exists; redacting here means it stays
/// safe even if one is added later.
impl Serialize for IdTokenFields {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("IdTokenFields", 1)?;
        state.serialize_field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))?;
        state.end()
    }
}

/// Hand-written rather than derived - a derived `Debug` would print the raw
/// id_token JWT in full whenever `{:?}` is used on the `OidcTokenResponse`
/// that embeds this (e.g. if debug logging is ever added to the token
/// exchange path), which is a credential leak. Redacts the value instead.
impl std::fmt::Debug for IdTokenFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdTokenFields")
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

type OidcTokenResponse = StandardTokenResponse<IdTokenFields, BasicTokenType>;
type OidcClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = Client<
    BasicErrorResponse,
    OidcTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

/// Builds a minimal synchronous HTTP client for oauth2's token/device-code
/// endpoint calls, built on our own `ureq` agent rather than pulling in
/// `reqwest` as a second HTTP client stack (oauth2's built-in
/// `reqwest-blocking` feature, or its `ureq` feature pinned to ureq ^2, would
/// each do that - this uses the crate's public `SyncHttpClient` trait
/// directly instead). Redirects are disabled (see the `max_redirects(0)`
/// below) - these requests carry the OAuth authorization code or
/// device-code grant in the body, and a compromised or misconfigured token
/// endpoint returning a redirect shouldn't cause that credential to be
/// silently resent to a different URL.
///
/// Returns a closure over one shared `Agent` rather than a plain function -
/// Microsoft's device-code flow polls this repeatedly until the user
/// completes sign-in, and building a fresh `Agent` (with its own connection
/// pool/TLS state) on every poll would be wasteful for a loop that can run
/// for minutes.
fn build_http_client() -> impl Fn(HttpRequest) -> Result<HttpResponse, ureq::Error> {
    // Same timeouts as client.rs's ApiClient::new - without them, a hung or
    // slow-to-respond token/device-code endpoint could block indefinitely;
    // on the Microsoft device-code path that would stall the main thread on
    // every single poll.
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        // Redirects disabled - same defense-in-depth rationale as
        // `client.rs`'s `raw_put`. These requests carry the OAuth
        // authorization code or device-code grant in the POST body; a
        // compromised or misconfigured token endpoint returning a redirect
        // would otherwise cause `ureq` to silently follow it and resend that
        // same credential to an attacker-controlled URL.
        .max_redirects(0)
        .timeout_connect(Some(std::time::Duration::from_secs(10)))
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    move |request: HttpRequest| -> Result<HttpResponse, ureq::Error> {
        let response = agent.run(request)?;
        // `http_status_as_error(false)` above means a 3xx status doesn't
        // itself become an `Err` the way 4xx/5xx would - combined with
        // `max_redirects(0)`, a redirecting token/device-code endpoint would
        // otherwise reach `oauth2` as an `Ok` 3xx response carrying an HTML
        // body, which it then tries to deserialize as a token response,
        // producing a confusing deserialization error instead of a clear
        // diagnostic about what actually happened.
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(ureq::Error::Io(std::io::Error::other(format!(
                "token/device-code endpoint returned an unexpected redirect (status {status}) instead of a token response"
            ))));
        }
        let (parts, mut body) = response.into_parts();
        // Capped, not a plain `body.read_to_vec()` - unlike `client.rs`'s
        // `send()` (which relies on ureq's own internal default limit), this
        // closure is on the Microsoft device-code polling path, which can
        // run repeatedly for up to 15 minutes - a single oversized response
        // from a malicious or misconfigured endpoint during that loop would
        // otherwise be fully buffered with no limit. 1MB is generous for any
        // real token/device-code response, which is normally a few hundred
        // bytes of JSON.
        const MAX_TOKEN_RESPONSE_BYTES: u64 = 1024 * 1024;
        let bytes = body
            .with_config()
            .limit(MAX_TOKEN_RESPONSE_BYTES)
            .read_to_vec()?;
        Ok(ureq::http::Response::from_parts(parts, bytes))
    }
}

pub(crate) fn login_google(config: &Config, account: Option<String>) {
    // Named to match the server's own env var for the same credential
    // (authenticate_controller.rb reads GOOGLE_AUTH_CLI_CLIENT_ID) rather
    // than a CLI-only name - the two must hold the identical client id for
    // SSO to work at all, and a mismatched naming convention between the two
    // halves of one credential is an easy deployment mistake to make with no
    // visual cue that they're paired.
    let client_id = std::env::var("GOOGLE_AUTH_CLI_CLIENT_ID").unwrap_or_else(|_| {
        eprintln!(
            "Google SSO isn't configured yet: set GOOGLE_AUTH_CLI_CLIENT_ID to the CLI's Desktop-app OAuth client id (the same value the server's GOOGLE_AUTH_CLI_CLIENT_ID env var must also be set to).\n\
             This requires a separate Google Cloud Console registration (Desktop app type) - see the plan's SSO prerequisite note."
        );
        std::process::exit(1);
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| {
        eprintln!("Could not bind a loopback port for the OAuth redirect: {e}");
        std::process::exit(1);
    });
    // Done here, before `open_browser` below, rather than inside
    // `await_redirect` (which used to run after the browser was already
    // opened) - if this rare `expect` ever panics (e.g. `fcntl` failing
    // under resource exhaustion), the user sees a clear terminal error
    // before their browser is committed to a redirect, instead of the
    // browser silently connecting to a port nothing is listening on.
    listener
        .set_nonblocking(true)
        .expect("can set the loopback listener non-blocking");
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| {
            eprintln!("Could not determine the loopback listener's port: {e}");
            std::process::exit(1);
        })
        .port();
    // The literal IPv4 loopback address, not the "localhost" hostname - the
    // listener above only binds 127.0.0.1 (IPv4), but on a dual-stack system
    // "localhost" often resolves to ::1 (IPv6) first, so the browser's
    // redirect would connect to a port nothing is listening on. RFC 8252
    // §7.3 (OAuth 2.0 for Native Apps) recommends the loopback IP literal
    // for exactly this reason.
    let redirect_uri = format!("http://127.0.0.1:{port}");

    // AuthUrl/TokenUrl are fixed, known-valid literals, and RedirectUrl is
    // built from a port number we just bound ourselves - none of these can
    // fail in practice, but exit cleanly rather than panic just in case.
    let client = OidcClient::new(ClientId::new(client_id))
        .set_auth_uri(
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .unwrap_or_else(|e| {
                    eprintln!("Invalid Google auth URL: {e}");
                    std::process::exit(1);
                }),
        )
        .set_token_uri(
            TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap_or_else(|e| {
                eprintln!("Invalid Google token URL: {e}");
                std::process::exit(1);
            }),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap_or_else(|e| {
            eprintln!("Invalid redirect URL: {e}");
            std::process::exit(1);
        }));

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // If `open_browser` fails to launch a browser automatically, its
    // fallback path prints the full `auth_url` - including the `state`
    // query parameter, which carries this exact `csrf_token`. Printing it
    // anywhere (terminal scrollback, CI log capture, a recorded session)
    // voids this session's CSRF protection: `await_redirect` below trusts
    // any connection whose `state` matches, so anyone who read that logged
    // value could craft a matching redirect. This is an accepted,
    // documented trade-off (see `open_browser`'s own comment) rather than a
    // bug - there's no way to let the user complete sign-in manually
    // without showing them the URL that contains it - but if the browser
    // fails to open and this URL does get logged somewhere, the safer move
    // is to cancel (Ctrl+C) and re-run `klaay login --google` for a fresh
    // token rather than trusting a redirect against a state value that may
    // no longer be secret.
    open_browser(auth_url.as_str());
    // Same Ctrl+C note as the Microsoft device-code flow below - this loop
    // can sit silently for up to 300s otherwise.
    println!("Waiting for sign-in... (press Ctrl+C to cancel)");

    let (mut code, mut stream) = await_redirect(
        listener,
        csrf_token.secret(),
        Duration::from_secs(300),
        Duration::from_secs(5),
    );

    let http_client = build_http_client();
    // `std::mem::take(&mut *code)`, not `code.to_string()` - the latter
    // clones the code into a *second*, separate heap allocation before
    // handing it to `AuthorizationCode::new` (an `oauth2`-crate type that
    // isn't zeroized internally), leaving that clone's bytes unprotected in
    // freed-but-not-cleared memory once `oauth2` drops it - on top of the
    // original still sitting in `code` itself. `mem::take` instead moves
    // the same single allocation out of the `Zeroizing` wrapper (leaving an
    // empty `String` behind, which zeroizes trivially on drop), so
    // `AuthorizationCode::new` receives the same bytes without this
    // codebase ever having created a second, redundant unprotected copy of
    // them. `oauth2` still holds that one copy unprotected either way -
    // this only closes the gap on our own side.
    let token_result = client
        .exchange_code(AuthorizationCode::new(std::mem::take(&mut *code)))
        .set_pkce_verifier(pkce_verifier)
        .request(&http_client);
    let token_result = match token_result {
        Ok(t) => t,
        Err(e) => {
            respond(
                &mut stream,
                "Sign-in failed - see the terminal for details.",
            );
            eprintln!("Token exchange failed: {e}");
            std::process::exit(1);
        }
    };

    // StandardTokenResponse's fields (including extra_fields) are private with
    // no consuming accessor (only `extra_fields(&self) -> &EF`), so cloning
    // the id_token is the only way to get an owned value through oauth2's
    // public API - verified directly against the crate source, not assumed.
    // `IdTokenFields.id_token` is `Option<Zeroizing<String>>`, so this clone
    // is already a `Zeroizing<String>` in its own right - both it and the
    // original inside `token_result` zero themselves on drop, rather than
    // only the clone (which a plain `String` field would leave unprotected).
    let id_token = token_result.extra_fields().id_token.clone();
    let id_token = match id_token {
        Some(t) => t,
        None => {
            respond(
                &mut stream,
                "Sign-in failed - see the terminal for details.",
            );
            eprintln!(
                "Google didn't return an id_token - check that the 'openid' scope was granted."
            );
            std::process::exit(1);
        }
    };

    // Sent only after `login_with_id_token` returns - it either completes
    // the login successfully or calls `process::exit` internally on any
    // failure (a rejected token, a network error, an unparseable response),
    // never returning to this line in that case. An earlier version sent
    // this success message *before* calling it, so a server-side failure
    // left the browser showing "You're signed in" while the CLI had, in
    // fact, failed - a false positive the user could easily miss if they'd
    // already stopped watching the terminal. `login_with_id_token` doesn't
    // have access to `stream` to send its own failure message on the way
    // out (it's shared with the plain password login path, which has no
    // browser at all) - accepting that a failure here leaves the browser tab
    // without an explicit message, rather than let it show one that's wrong.
    auth::login_with_id_token(config, auth::SsoProvider::Google, id_token, account);
    respond(
        &mut stream,
        "You're signed in - you can close this window and return to the terminal.",
    );
}

pub(crate) fn login_microsoft(config: &Config, account: Option<String>) {
    // Named to match the server's own env var for the same credential
    // (authenticate_controller.rb reads MICROSOFT_AUTH_CLI_CLIENT_ID) - see
    // the matching comment in login_google above for why this naming
    // consistency matters.
    let client_id = std::env::var("MICROSOFT_AUTH_CLI_CLIENT_ID").unwrap_or_else(|_| {
        eprintln!(
            "Microsoft SSO isn't configured yet: set MICROSOFT_AUTH_CLI_CLIENT_ID to the CLI's public-client Entra app id (the same value the server's MICROSOFT_AUTH_CLI_CLIENT_ID env var must also be set to).\n\
             This requires a separate Azure Entra registration (public client, device-code flow enabled) - see the plan's SSO prerequisite note."
        );
        std::process::exit(1);
    });
    let tenant =
        std::env::var("MICROSOFT_AUTH_CLI_TENANT").unwrap_or_else(|_| "organizations".to_string());
    // Interpolated directly into the auth/token/device-code URLs below - reject
    // anything with path-traversal or other URL-special characters (a tenant
    // like "common/../../evil" would otherwise restructure the request path).
    // Real tenant values are always a UUID, a domain name, or one of a few
    // fixed keywords, all of which fit this allowlist.
    // `chars().count()`, not `len()` - the latter counts bytes, not Unicode
    // characters, so with the current ASCII-only allowlist below they always
    // agree (every allowed character is one byte), but this stays correct if
    // that allowlist is ever widened to admit multi-byte characters, matching
    // what the error message actually says.
    if tenant.chars().count() > 253 {
        eprintln!("MICROSOFT_AUTH_CLI_TENANT is too long (max 253 characters): {tenant:?}");
        std::process::exit(1);
    }
    // `is_ascii_alphanumeric` (not `is_alphanumeric`) - the latter accepts
    // any Unicode letter/digit (e.g. 'é', '中'), none of which are valid in
    // a real Azure tenant identifier, and interpolating one into the
    // auth/token/device-code URLs below could produce a malformed request.
    // This same character-level check already rejects '%' (it's not
    // alphanumeric, '-', or '.'), so a percent-encoded value like
    // "common%2F..%2Fevil" is caught here directly - verified empirically -
    // without needing a separate `contains('%')` check.
    // Real tenant values (a UUID, a domain like "contoso.com", or a keyword
    // like "common"/"organizations") never start/end with '-'/'.' and never
    // contain "..", so rejecting those shapes too closes off a value like
    // ".." that would otherwise pass the character allowlist and restructure
    // the request path when interpolated into the URLs below.
    if !tenant
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        || tenant.starts_with('.')
        || tenant.ends_with('.')
        || tenant.contains("..")
        || tenant.starts_with('-')
        || tenant.ends_with('-')
    {
        // Not "contains invalid characters" - some of the rejections above
        // (leading/trailing '-'/'.', or "..") are structural, not a
        // character outside the allowlist, so a value like "common..org"
        // would otherwise be reported with a message that doesn't actually
        // describe why it failed.
        eprintln!(
            "MICROSOFT_AUTH_CLI_TENANT is not a valid Azure tenant identifier (must contain only alphanumerics, hyphens, and dots, and must not start/end with - or ., or contain \"..\"): {tenant:?}"
        );
        std::process::exit(1);
    }

    let client = OidcClient::new(ClientId::new(client_id))
        .set_auth_uri(
            AuthUrl::new(format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
            ))
            .unwrap_or_else(|e| {
                eprintln!("Invalid Microsoft auth URL: {e}");
                std::process::exit(1);
            }),
        )
        .set_token_uri(
            TokenUrl::new(format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            ))
            .unwrap_or_else(|e| {
                eprintln!("Invalid Microsoft token URL: {e}");
                std::process::exit(1);
            }),
        )
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new(format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
            ))
            .unwrap_or_else(|e| {
                eprintln!("Invalid Microsoft device authorization URL: {e}");
                std::process::exit(1);
            }),
        );

    let http_client = build_http_client();
    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .request(&http_client)
        .unwrap_or_else(|e| {
            eprintln!("Could not start device-code sign-in: {e}");
            std::process::exit(1);
        });

    // Prefers the combined URI (code pre-filled) when the endpoint returns
    // one - one link to open rather than a URL to visit plus a code to
    // retype by hand, and less time the code sits readable in terminal
    // scrollback/CI logs. `VerificationUriComplete`/`UserCode` are both
    // `new_secret_type!` wrappers (like `DeviceCode`), so `.secret()` is the
    // real accessor here - there's no `.as_str()` on either.
    match details.verification_uri_complete() {
        Some(uri) => println!("To sign in, open this link: {}", uri.secret()),
        None => println!(
            "To sign in, visit {} and enter code {}",
            details.verification_uri().as_str(),
            details.user_code().secret()
        ),
    }
    // No SIGINT handler is registered anywhere in this crate, so Ctrl+C
    // already terminates the process immediately via the OS default - this
    // is just telling the user that, since the poll below can otherwise sit
    // silently for up to 15 minutes with no other feedback, which looks
    // indistinguishable from a hang.
    println!("Waiting for sign-in... (press Ctrl+C to cancel)");

    // Caps the server-reported expiry rather than trusting it outright - a
    // compromised or misbehaving device-authorization endpoint could return
    // an arbitrarily large value (e.g. u64::MAX seconds), which would
    // otherwise make the CLI poll indefinitely.
    let poll_duration = details.expires_in().min(Duration::from_secs(15 * 60));
    let token_result = client
        .exchange_device_access_token(&details)
        .request(&http_client, std::thread::sleep, Some(poll_duration))
        .unwrap_or_else(|e| {
            eprintln!("Device-code sign-in failed: {e}");
            std::process::exit(1);
        });

    // Same rationale as login_google above - `id_token` is already
    // `Zeroizing<String>` since `IdTokenFields.id_token` is, so both this
    // clone and the original inside `token_result` zero on drop.
    let id_token = token_result
        .extra_fields()
        .id_token
        .clone()
        .unwrap_or_else(|| {
            eprintln!(
                "Microsoft didn't return an id_token - check that the 'openid' scope was granted."
            );
            std::process::exit(1);
        });

    auth::login_with_id_token(config, auth::SsoProvider::Microsoft, id_token, account);
}

/// Waits (up to `accept_timeout`) for the real OAuth redirect, reads the HTTP
/// request line-by-line until the blank line that ends the headers (a single
/// `read()` call is not guaranteed to receive the whole request - TCP can
/// split it across segments), and parses `code`/`state` from the redirect's
/// query string using a real URL-decoder rather than raw string splitting
/// (OAuth2 redirect params can be percent-encoded). Returns the still-open
/// stream so the caller can respond only after exchanging the code, instead
/// of telling the browser "you're signed in" before that has actually
/// happened.
///
/// Accepting is done on a background thread that blocks in `accept()` and
/// forwards each connection over a channel - avoids a busy-poll sleep loop
/// on the main thread, which would otherwise burn CPU waking up every 200ms
/// for the full accept window. The main thread loops over connections
/// (bounded by the same overall deadline) rather than trusting the first one:
/// any other local process racing to connect to the loopback port before the
/// real browser redirect arrives - or the user opening the callback URL by
/// hand a second time - would otherwise steal the one accept this function
/// used to make and abort the flow on a connection carrying no real code.
///
/// `state` is checked against `expected_state` *before* anything in the
/// request is trusted - including an `?error=...` response. A connection
/// whose state doesn't match `expected_state` (no state at all, or a value
/// that isn't our own CSRF token) is treated as spurious and ignored rather
/// than honored: without this check, any other local process could connect
/// to the loopback port first with a crafted `?error=access_denied` and abort
/// the user's real, still-pending sign-in - a local denial-of-service the
/// original code was vulnerable to, since it acted on `error` unconditionally
/// as soon as any connection carried one, deferring the state comparison to
/// after this function had already returned (or, worse, already exited the
/// process on the error path, before state was ever checked at all).
///
/// The background accept thread is nonblocking and polls a shared stop flag
/// rather than blocking forever in `accept()` - on the success path below,
/// this function sets the flag and joins the thread before returning, so the
/// listener socket is deterministically closed here rather than left to
/// whenever (if ever) another stray connection happens to wake the old
/// blocking `accept()` call. The `std::process::exit` paths elsewhere in this
/// function don't need the same treatment - the whole process (and every one
/// of its threads/sockets) is torn down by the OS at that point regardless.
fn await_redirect(
    listener: TcpListener,
    expected_state: &str,
    accept_timeout: Duration,
    read_timeout: Duration,
) -> (zeroize::Zeroizing<String>, TcpStream) {
    // Non-blocking mode is set by the caller (`login_google`), before
    // `open_browser` runs - see the comment at the `TcpListener::bind` call
    // site for why.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_for_thread = std::sync::Arc::clone(&stop);
    // Bounded (not `mpsc::channel()`'s unbounded queue) - the accept thread
    // takes every incoming TCP connection with no filtering until
    // `await_redirect_loop` reads and validates its `state` param, so a flood
    // of connections (browser prefetch, automated retries, or a local
    // process hammering this port) would otherwise let accepted `TcpStream`s
    // (each holding an OS file descriptor) pile up in the channel faster
    // than they're consumed. A bounded channel makes `tx.send` block once
    // full, which throttles the accept loop itself instead of accumulating
    // unbounded open file descriptors.
    let (tx, rx) = mpsc::sync_channel(4);
    let handle = std::thread::spawn(move || loop {
        // `Acquire` (paired with the main thread's `Release` store below) -
        // `Relaxed` only guarantees the flag's own atomicity, not that any
        // other main-thread writes preceding the store are visible here once
        // this thread observes `true`. Not exploitable today (this thread
        // reads nothing else the main thread wrote before signaling stop),
        // but `Acquire`/`Release` is the correct idiom for a shutdown flag
        // and costs nothing extra on the platforms this crate targets.
        if stop_for_thread.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if tx.send(stream).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    });

    let (code, stream) = await_redirect_loop(&rx, expected_state, accept_timeout, read_timeout);
    stop.store(true, std::sync::atomic::Ordering::Release);
    // Dropped explicitly, before `join`, not left to drop naturally at the
    // end of this function - `await_redirect_loop` only ever borrows `rx`
    // (`&rx`), so the owned receiver is still alive at this point. If the
    // accept thread is currently blocked inside its own `tx.send(stream)`
    // (the bounded channel's capacity is 4 - reachable from a connection
    // flood, exactly the scenario that bound was added for), the stop flag
    // it checks is only read at the *top* of its loop, never while blocked
    // inside `send`. Confirmed empirically (a throwaway program mirroring
    // this exact structure) that without dropping `rx` first, `join()`
    // below genuinely never returns: `SyncSender::send` only unblocks once
    // the receiver either reads a value or is dropped, and nothing here
    // does either until this drop.
    drop(rx);
    let _ = handle.join();
    (code, stream)
}

fn await_redirect_loop(
    rx: &mpsc::Receiver<TcpStream>,
    expected_state: &str,
    accept_timeout: Duration,
    read_timeout: Duration,
) -> (zeroize::Zeroizing<String>, TcpStream) {
    let deadline = Instant::now() + accept_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            eprintln!("Timed out waiting for the browser sign-in redirect.");
            std::process::exit(1);
        }
        let mut stream = match rx.recv_timeout(remaining) {
            Ok(stream) => stream,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                eprintln!("Timed out waiting for the browser sign-in redirect.");
                std::process::exit(1);
            }
            // Distinct from a real timeout - this means the accept thread's
            // sender (`tx`) was dropped because that thread exited its loop
            // on some I/O error other than `WouldBlock` (e.g. `EMFILE`, too
            // many open file descriptors). Conflating the two (as a single
            // `Err(_)` arm would) reports a confusing "timed out" message
            // for what's actually an accept-thread failure - the loopback
            // listener may have stopped accepting connections well before
            // the real timeout ever elapsed.
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!(
                    "Internal error: the loopback listener's accept thread exited unexpectedly."
                );
                std::process::exit(1);
            }
        };
        // `unwrap_or_else` + `process::exit` (not `.expect()`) - matching
        // every other error path in this file. A panic here would unwind
        // through this function and its caller (`await_redirect`) before
        // `drop(rx)`/`handle.join()` are reached, leaving the accept thread
        // alive with a live `tx` sender that keeps looping and consuming
        // connections indefinitely instead of a clean process exit.
        stream
            .set_read_timeout(Some(read_timeout))
            .unwrap_or_else(|e| {
                eprintln!("Could not set read timeout on connection: {e}");
                std::process::exit(1);
            });
        // Mirrors the read timeout - without this, `respond()`'s
        // `write_all` call (made by the caller after this stream is
        // returned) could block the main thread indefinitely if the peer
        // (the browser, or another local process racing to hit this port)
        // stalls the connection after sending the redirect but before
        // reading the response.
        stream
            .set_write_timeout(Some(read_timeout))
            .unwrap_or_else(|e| {
                eprintln!("Could not set write timeout on connection: {e}");
                std::process::exit(1);
            });

        let (request_line, complete) = read_request_headers(&mut stream, read_timeout);
        // A truncated request (cut off by the 64KB limit, a timeout, or the
        // connection closing early) is treated as spurious rather than
        // parsed - the request line captured so far might still happen to
        // carry a matching `state`/`code`, but there's no guarantee the rest
        // of what the browser actually sent survived, so this can't be
        // trusted as the real, complete redirect. The warnings inside
        // `read_request_headers` already told the user why, if relevant.
        if !complete {
            respond(
                &mut stream,
                "Waiting for the real sign-in redirect - you can close this window.",
            );
            continue;
        }
        let path = request_line.split_whitespace().nth(1).unwrap_or("");
        let query = path.split_once('?').map(|x| x.1).unwrap_or("");

        // `Zeroizing<String>` from creation, not just wrapped at the final
        // `return` below - `code` is dropped as a plain `String` on both
        // `continue` paths further down (a state mismatch, or an empty code
        // with no error), and a state-mismatched request can still carry a
        // non-empty `code` value that would otherwise leave its bytes
        // unzeroed on the heap. Declaring it `Zeroizing` here means every
        // loop iteration's end - whether via `continue` or the final
        // `return` - zeroizes it via `Drop`.
        let mut code = zeroize::Zeroizing::new(String::new());
        let mut state = String::new();
        let mut oauth_error = String::new();
        let mut oauth_error_description = String::new();
        // Only the *first* occurrence of each key is accepted - a plain
        // last-write-wins `match` would let a local process racing this
        // loopback port inject a second `code=`/`error=` pair after the
        // real one, substituting a different value once the `state` check
        // below passes (the real value already having matched what this
        // process itself generated).
        //
        // `error`/`error_description` are capped at `MAX_ERROR_LEN` chars
        // right here at parse time, not just later at display time - the
        // query string is only bounded by `read_request_headers`'s 64KB
        // limit, so without this cap a state-matching local attacker could
        // still force a full ~64KB `v.into_owned()` allocation per field
        // before any truncation ever ran. `code`/`state` aren't capped here:
        // both are validated against fixed real-world shapes shortly after
        // this loop (a JWT/OAuth code and a 22-character CSRF token,
        // respectively) that are already far under this length, so an
        // oversized value there is caught downstream instead.
        const MAX_ERROR_LEN: usize = 512;
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            match k.as_ref() {
                // `push_str`, not `*code = v.into_owned()` - `into_owned()`
                // on a `Cow::Borrowed` (the common case) allocates a plain,
                // non-`Zeroizing` `String` that's then moved into `*code`,
                // leaving that intermediate allocation's bytes unzeroed on
                // the heap. `code` starts empty (guaranteed by the guard
                // above matching only the first occurrence), so `push_str`
                // copies the decoded bytes directly into the already-
                // `Zeroizing`-wrapped buffer without an unprotected
                // intermediate ever existing.
                "code" if code.is_empty() => code.push_str(&v),
                "state" if state.is_empty() => state = v.into_owned(),
                "error" if oauth_error.is_empty() => {
                    oauth_error = v.chars().take(MAX_ERROR_LEN).collect();
                }
                "error_description" if oauth_error_description.is_empty() => {
                    oauth_error_description = v.chars().take(MAX_ERROR_LEN).collect();
                }
                _ => {}
            }
        }

        // A connection whose state doesn't match ours can't be the real
        // provider redirect - it's a stray local probe, a favicon request,
        // the user opening the loopback URL by hand, or (the case this
        // guards against) another local process racing to hit this port
        // with a crafted error/code before the real redirect arrives. Treat
        // it as spurious and keep waiting, rather than trusting its `error`
        // or `code` at all.
        // Constant-time, not `!=` - the state is a single-use CSRF token,
        // but a local adversary able to make rapid repeated loopback
        // connections to this port could otherwise use timing differences
        // in a naive byte-by-byte `!=` comparison to guess its *content* one
        // character at a time before the real redirect arrives. `[u8]::
        // ct_eq` itself does short-circuit (near-instantly) when the two
        // slices' lengths differ rather than doing the full per-byte
        // comparison - a theoretically observable timing difference between
        // "wrong length" and "right length, wrong content" - but that only
        // ever reveals `expected_state`'s *length*, and that length is not a
        // secret to protect: `oauth2::CsrfToken::new_random()` (used to
        // generate it, see `login_google`/`login_microsoft`) always calls
        // `new_random_len(16)` - a fixed 16 random bytes, base64url-encoded
        // to a fixed 22-character string, every single time, for every
        // consumer of the crate. Confirmed directly against the installed
        // oauth2 5.0.0 source rather than assumed. An earlier revision added
        // a redundant `Choice`-based length pre-check here in response to a
        // review comment - it didn't actually change `ct_eq`'s own internal
        // short-circuit behavior (still called unconditionally either way),
        // so it added complexity without closing any real gap; removed.
        if state
            .as_bytes()
            .ct_eq(expected_state.as_bytes())
            .unwrap_u8()
            == 0
        {
            respond(
                &mut stream,
                "Waiting for the real sign-in redirect - you can close this window.",
            );
            continue;
        }

        // The provider redirected back with an error (e.g. the user clicked
        // "deny") instead of a code - report that directly rather than firing
        // a token exchange with an empty code and surfacing whatever opaque
        // error Google/Microsoft's token endpoint happens to return for it.
        if !oauth_error.is_empty() {
            respond(
                &mut stream,
                "Sign-in was not completed - you can close this window and return to the terminal.",
            );
            // Sanitized before printing - the state check above only
            // confirms this connection carries *our* CSRF state, not that
            // its query string is otherwise trustworthy. A local attacker
            // racing this loopback port with a state-matching request could
            // still control `error`/`error_description` freely, and printing
            // them raw would let terminal control/escape sequences reach the
            // user's terminal (cursor movement, color, screen clear, etc).
            // Already capped to `MAX_ERROR_LEN` chars back at the parse loop
            // above (not re-truncated here) - that's what keeps a
            // state-matching attacker's oversized `error`/`error_description`
            // value from ever being fully allocated in the first place,
            // rather than truncating a copy of it after the fact.
            let oauth_error = sanitize_for_display(&oauth_error);
            let oauth_error_description = sanitize_for_display(&oauth_error_description);
            if oauth_error_description.is_empty() {
                eprintln!("Sign-in was not completed: {oauth_error}");
            } else {
                eprintln!("Sign-in was not completed: {oauth_error} - {oauth_error_description}");
            }
            // Closed explicitly before exiting - without this, the OS closes
            // the socket via the process teardown instead, which sends a TCP
            // RST rather than a clean FIN. The browser may then show a
            // connection-reset error instead of rendering the response
            // `respond()` just wrote above.
            drop(stream);
            std::process::exit(1);
        }

        if code.is_empty() {
            // State matched but there's no code and no error - malformed
            // redirect. Keep waiting rather than aborting the whole flow.
            respond(
                &mut stream,
                "Waiting for the real sign-in redirect - you can close this window.",
            );
            continue;
        }

        // `code` is already `Zeroizing<String>` (wrapped at declaration
        // above, for every loop exit, not just this one) - the code is a
        // short-lived, single-use credential (it grants exchanging for
        // tokens until either used once or it expires) and this codebase
        // already treats every other credential-shaped value (password,
        // id_token, bearer tokens) the same way. Note this only protects our
        // own copy: `AuthorizationCode::new()` below takes ownership of a
        // plain `String` and the `oauth2` crate's own internals aren't
        // zeroized either, so the protection this actually buys is the
        // window between receiving the code over the socket and handing it
        // off - not its whole lifetime in memory.
        return (code, stream);
    }
}

/// Reads HTTP request lines until the blank line terminating the headers.
/// Bounds the *underlying* read to 64KB via `Read::take` (not just the
/// accumulated `String`) - a single crafted line with no newline would
/// otherwise let a single `read_line` call buffer an unbounded amount before
/// any length check on the accumulator ever ran. 64KB (rather than the
/// original 8KB) gives real browser redirects - which can carry a sizeable
/// `Cookie`/`Referer` header - enough headroom that a legitimate request
/// isn't truncated mid-header and silently rejected as spurious. Also caps
/// the *number* of lines read (not just total bytes) - a connection sending
/// many one-byte lines with no terminator would otherwise still fit inside
/// the 64KB byte budget while forcing hundreds of separate `read_line` calls,
/// each able to block for the full per-connection `read_timeout`.
///
/// Deliberately keeps *reading* through every header line (Cookie,
/// User-Agent, Referer, etc.) even though only the first is ever returned -
/// stopping the socket read early after just the request line, as a pure
/// "only read what's used" optimization would, leaves the rest of the
/// browser's request sitting unread in the kernel's receive buffer. Writing
/// a response and closing the connection with unread incoming data still
/// pending is exactly the condition that makes the OS send a TCP RST instead
/// of a clean FIN (the same class of issue this file's `oauth_error` path
/// was fixed to avoid, via `drop(stream)` before `process::exit`) - so fully
/// draining the request here isn't wasted work, it's what lets `respond()`'s
/// later write land as a clean close instead of a reset the browser might
/// render as a network error. This is separate from *accumulating* what's
/// read: every line past the first is parsed off the wire (to find the
/// blank-line terminator and to count bytes/lines against the limits below)
/// and then dropped - only the request line itself is kept, since the
/// caller never inspects anything past it.
/// Returns the request line alongside whether the blank-line terminator was
/// actually seen - a plain `String` gave the caller no way to distinguish a
/// genuinely complete request from one cut off by the 64KB limit, a
/// timeout, or the connection closing early. Without that distinction, a
/// truncated request whose request line happened to already carry a
/// matching `state` and `code` (i.e. only later headers were lost) would
/// still be accepted, defeating the point of having a hard limit at all as
/// an acceptance gate.
fn read_request_headers(stream: &mut TcpStream, read_timeout: Duration) -> (String, bool) {
    const MAX_HEADER_LINES: usize = 100;
    const MAX_HEADER_BYTES: u64 = 65536;
    let bounded = stream.take(MAX_HEADER_BYTES);
    let mut reader = BufReader::new(bounded);
    let mut request_line = String::new();
    // Tracks bytes actually read off the wire, not `request.len()` - the
    // latter only ever reflects *complete* lines that were pushed into
    // `request`, so it would never include whatever partial, still-
    // incomplete line consumed the last of `Read::take`'s budget. Counted
    // immediately after `read_line` returns, before branching on `n == 0` -
    // an earlier revision counted only on the non-`n == 0` path, so by the
    // time the budget was actually exhausted, `bytes_read` reflected only
    // the previously *completed* lines and could never reach
    // `MAX_HEADER_BYTES`, silently defeating the warning below.
    let mut bytes_read: u64 = 0;
    // A single wall-clock deadline for the whole header read, not just a
    // per-`read_line` timeout re-armed every iteration - `set_read_timeout`
    // bounds each individual call, not the total time spent in this
    // function, so without this a connection that drip-feeds one byte per
    // line with no newline terminator could stall here for up to
    // `MAX_HEADER_LINES * read_timeout` (100 * 5s = 500s by the caller's
    // current timeout), far past the single connection's intended budget.
    // `get_ref().get_ref()` unwraps `BufReader<Take<&mut TcpStream>>` back
    // down to the underlying stream so the timeout can be adjusted; `Take`
    // has no read-timeout concept of its own; the timeout lives on the
    // socket underneath it.
    let deadline = Instant::now() + read_timeout;
    // Only set `true` at the blank-line terminator below - every other exit
    // from this loop (timeout, budget exhausted, connection closed early,
    // or the `MAX_HEADER_LINES` cap reached with no blank line ever seen)
    // leaves this `false`, signaling to the caller that the request is
    // truncated and shouldn't be trusted as a complete one.
    let mut complete = false;
    // Tracks whether one of the loop's own `break` paths already printed a
    // warning explaining why `complete` is `false` - every path does except
    // the loop naturally exhausting all `MAX_HEADER_LINES` iterations
    // without ever seeing a blank-line terminator, which needs its own
    // warning after the loop instead.
    let mut warned = false;
    for _ in 0..MAX_HEADER_LINES {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            eprintln!(
                "Warning: OAuth redirect request took too long to send its headers - sign-in may not complete."
            );
            warned = true;
            break;
        }
        if reader
            .get_ref()
            .get_ref()
            .set_read_timeout(Some(remaining))
            .is_err()
        {
            eprintln!(
                "Warning: could not set read timeout on OAuth redirect connection - skipping."
            );
            warned = true;
            break;
        }
        let mut line = String::new();
        // A `TimedOut`/`WouldBlock` error (from the dynamically-shrinking
        // per-iteration `remaining` timeout set above) is not the same as a
        // genuine EOF - `unwrap_or(0)` used to collapse both into the same
        // `n == 0` branch, so a browser that was just slow to send its final
        // header line (or one whose read happened to straddle a timeout
        // boundary) was silently treated as a truncated/closed connection,
        // even though the observable outcome (rejecting this attempt as
        // spurious, `complete` stays `false`) is the same either way -
        // distinguishing them just gives an accurate diagnostic instead of
        // misattributing a timeout to budget exhaustion.
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                eprintln!(
                    "Warning: OAuth redirect request took too long to send its headers - sign-in may not complete."
                );
                warned = true;
                break;
            }
            Err(e) => {
                eprintln!(
                    "Warning: I/O error reading OAuth redirect request headers: {e} - sign-in may not complete."
                );
                warned = true;
                break;
            }
        };
        bytes_read += n as u64;
        if n == 0 {
            // Indistinguishable, from `read_line`'s return value alone,
            // between "the connection closed" and "the 64KB byte budget ran
            // out before a blank line was ever read" - checking the real
            // running byte count against the budget disambiguates the two,
            // so a truncated-but-real request is reported instead of
            // silently discarded as spurious (which would otherwise leave
            // the user waiting out the full accept timeout with no
            // indication their browser's redirect actually arrived).
            if bytes_read >= MAX_HEADER_BYTES {
                eprintln!(
                    "Warning: OAuth redirect request headers exceeded the read limit and were truncated - sign-in may not complete."
                );
                warned = true;
            }
            break;
        }
        if line == "\r\n" || line == "\n" {
            complete = true;
            break;
        }
        // Only the request line itself is kept - every later header line is
        // still fully read off the wire (see the doc comment above) but
        // discarded here rather than appended, since the caller never
        // inspects anything past the request line.
        if request_line.is_empty() {
            request_line = line;
        }
    }
    // Covers the remaining silent paths: the loop exhausting all
    // `MAX_HEADER_LINES` iterations without ever seeing a blank-line
    // terminator (the case this was added for), and the connection closing
    // (`n == 0`) before the byte budget was reached. Every other exit from
    // this loop already printed its own specific warning above (tracked via
    // `warned`) - without this, those remaining paths left the caller
    // silently waiting with no indication anything went wrong.
    if !complete && !warned {
        eprintln!(
            "Warning: OAuth redirect request ended without a complete set of headers - sign-in may not complete."
        );
    }
    (request_line, complete)
}

/// Replaces every control character (which includes CR/LF/NUL, and every
/// ANSI escape sequence's leading ESC byte) with `?` before a value that
/// ultimately came from the redirect's query string is ever printed to the
/// terminal via `eprintln!`. The CSRF `state` check happening earlier only
/// proves *a* request carrying our state arrived - not that the rest of its
/// query string is trustworthy, since a local attacker racing this loopback
/// port could still craft `error`/`error_description` freely. Without this,
/// those values could inject terminal escape sequences (cursor movement,
/// color, screen clear, or worse on some terminal emulators).
fn sanitize_for_display(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control()
                || matches!(c,
                    // Unicode BiDi override/isolate characters - Unicode
                    // category Cf (format), not Cc, so `is_control()` alone
                    // misses them (confirmed directly: `'\u{202E}'.is_control()`
                    // is `false`). A terminal that renders BiDi text can use
                    // these to visually reorder the displayed string, which
                    // defeats the point of sanitizing at all.
                    '\u{200E}' | '\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{2028}' | '\u{2029}'
                    // Unicode Tags block - invisible, historically used to
                    // embed hidden data in text; also Cf (format), not Cc,
                    // so `is_control()` misses these too (confirmed
                    // empirically, same as the BiDi characters above).
                    | '\u{E0000}'..='\u{E007F}'
                    // Interlinear Annotation Anchor/Separator/Terminator -
                    // Cf category, same gap.
                    | '\u{FFF9}'..='\u{FFFB}'
                )
            {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// `&'static str` (not `&str`) is a compile-time guarantee, not just a
/// convention, that only fixed literals reach this function - a future
/// caller that tried to pass user-controlled content (e.g. an OAuth error
/// description) straight into this raw-HTTP-building function would get a
/// type error instead of a silent header-injection footgun. Still
/// sanitizes CRLF/NUL below as defense in depth.
///
/// Shuts down the write half of `stream` before returning (see below), so
/// callers must not write to `stream` again afterwards - the OS will accept
/// the syscall but the peer will never see the bytes. Every current caller
/// only reads from (or drops) `stream` after calling this.
fn respond(stream: &mut TcpStream, message: &'static str) {
    let safe_message = message.replace(['\r', '\n', '\0'], " ");
    // `.len()` (used for Content-Length below) is already the byte length of
    // a `String`/`&str`, not a char count - there's no separate byte count
    // to fall out of sync with what `write_all` actually sends.
    // `Connection: close` - without it, HTTP/1.1's keep-alive default means
    // the browser holds the connection open waiting for a next response
    // that never comes, and only sees a TCP RST (once the caller drops this
    // `TcpStream`, whether by returning normally or via `process::exit`)
    // instead of a clean connection close. Many browsers render that RST as
    // a network-error page even though the real response body was already
    // fully received, so the user would see an error page instead of the
    // "you're signed in" message this was meant to show.
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{}",
        safe_message.len(),
        safe_message
    );
    // A write timeout is set on this stream (`await_redirect_loop`'s 5s
    // `read_timeout`, reused for writes too), so a partial write or a
    // complete failure here (peer disconnected, write timed out) is a real
    // possibility, not just a theoretical one - `eprintln!` on failure gives
    // a diagnostic instead of silently leaving the browser without its
    // "you're signed in" message with no indication anything went wrong.
    if let Err(e) = stream.write_all(response.as_bytes()) {
        eprintln!("Warning: could not send browser response: {e}");
    }
    // Signals end-of-response immediately rather than relying solely on the
    // `Connection: close` header plus the caller's eventual `drop(stream)` -
    // if the caller holds the stream open for a while after this call
    // returns (e.g. `await_redirect_loop`'s success path does more work
    // before returning), the browser would otherwise wait on the connection
    // even though every byte of the response already arrived.
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

/// Uses the `open` crate rather than hand-rolled per-OS `Command` invocations.
/// The previous Windows branch shelled out via `cmd /C start`, which is
/// vulnerable to injection from an OAuth2 URL's own query string (`&`, `^`,
/// `%` are all cmd.exe-significant and always present in a real auth URL).
/// `open` calls the platform's native launch API (e.g. `ShellExecute` on
/// Windows) directly instead of going through a shell.
/// Prints the "Opening..." message only after `open::that` actually
/// succeeds, rather than unconditionally before attempting it - printing it
/// first meant a failed launch still showed a misleading "Opening ... in
/// your browser..." line immediately followed by "Could not open a browser
/// automatically", which reads as contradictory.
fn open_browser(url: &str) {
    match open::that(url) {
        // Doesn't print `url` here - it carries the CSRF state token and
        // PKCE code challenge in its query string, which the user doesn't
        // need to see (the browser already has it) and shouldn't end up in
        // terminal scrollback/CI log captures/shell history. The failure
        // branch below still has to print it - the user needs the full URL
        // to open it manually - so the exposure isn't eliminated, only
        // limited to the path that actually requires it.
        Ok(()) => println!("Opening your browser for sign-in..."),
        Err(e) => {
            eprintln!("Could not open a browser automatically ({e}).");
            eprintln!("Please open the following URL manually: {url}");
            // Surfaced to the user, not just documented in the comment above -
            // this URL carries a one-time CSRF state token; if it ends up
            // visible in shared logs/terminal history, whoever completes
            // sign-in with it may be using a token that's already been seen.
            eprintln!(
                "Warning: this URL contains a one-time CSRF token. If it appears in logs or shared terminal history, press Ctrl+C and re-run to get a fresh token."
            );
        }
    }
}
