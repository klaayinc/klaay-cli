// SPDX-License-Identifier: GPL-3.0-or-later
use crate::auth;
use crate::client::ApiClient;
use crate::config::Config;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

// Browser sign-in through kiln's /cli_auth_requests mailbox. This process
// never talks to an identity provider and needs no OAuth client
// registration: it opens the normal Klaay login page, which supports every
// sign-in method the deployment has, and the server mints the long-lived
// `client: "cli"` token once the signed-in user approves.
//
// Two shapes, picked by whether a browser can reach this machine.
//
// Loopback (the default). We bind 127.0.0.1 first, tell the server which
// port, and keep a verifier whose SHA-256 the server stores. The browser is
// sent back to that port with a one-time code. A remote attacker cannot
// receive a redirect to our loopback address, so the token binds to this
// machine without anyone judging anything. RFC 8252 §8.10 notes another
// local program can sometimes read the loopback response; it still cannot
// use the code, because the verifier never leaves this process.
//
// Device (--no-browser, or when no browser opens). The server issues two
// values. The long one stays here and never appears in a URL or on screen.
// The short one is printed for the person to type into a page they opened
// themselves - so there is no link to send, and the one-click approval
// attack has nothing to click.

/// Matches the server's CliAuthRequest::TTL (5 minutes) plus slack: the
/// normal end is the server answering 404 once the request expires, this
/// deadline is only the local backstop if that never arrives.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(360);
/// Well under the claim endpoint's 60/minute rate-limit bucket.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Nobody remote can receive a redirect here, so the token binds to this
/// machine. Named so a test can assert the address this code binds, not one
/// the test binds itself.
fn bind_loopback() -> std::io::Result<TcpListener> {
    TcpListener::bind("127.0.0.1:0")
}

pub(crate) fn login_via_browser(config: &Config, no_browser: bool) {
    if no_browser {
        login_via_device(config);
        return;
    }

    // Bound before registering: the server needs the real port, and the OS
    // only names it once the socket exists.
    let listener = match bind_loopback() {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Could not listen on 127.0.0.1 for the sign-in reply ({e}).");
            eprintln!("Falling back to the code you type in yourself.");
            login_via_device(config);
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            eprintln!("Could not read the local sign-in port ({e}).");
            login_via_device(config);
            return;
        }
    };

    let verifier = random_secret();
    let challenge = challenge_for(&verifier);
    let client = ApiClient::new(config.api_url().to_string(), None);

    let response = register(
        config,
        &client,
        &format!(
            r#"{{"data":{{"type":"cli_auth_requests","attributes":{{"kind":"loopback","client":"cli","code_challenge":"{challenge}","redirect_port":{port}}}}}}}"#
        ),
    );
    let request_id = match string_attribute(&response, "request_id") {
        Some(id) => id,
        None => {
            eprintln!("The server accepted the sign-in but named no request to approve.");
            std::process::exit(1);
        }
    };

    let web_url = resolve_web_url(config, &response);
    // The request id is not a secret - it selects a row and nothing more, so
    // it is safe in an address bar, a browser history, or an error report.
    // Only the verifier, which stays in this process, can claim the token.
    let url = format!("{web_url}/login?app=cli&request={request_id}");
    if !open_browser(&url) {
        eprintln!("Falling back to the code you type in yourself.");
        login_via_device(config);
        return;
    }
    println!("Waiting for you to finish signing in... (press Ctrl+C to cancel)");

    let code = match wait_for_code(listener) {
        Some(code) => code,
        None => {
            eprintln!("The browser never came back with a sign-in reply.");
            std::process::exit(1);
        }
    };

    let body = zeroize::Zeroizing::new(format!(
        r#"{{"data":{{"type":"cli_auth_requests","attributes":{{"code":"{}","code_verifier":"{}"}}}}}}"#,
        &*code, &*verifier
    ));
    let response = client.raw_post(
        &format!("{}/cli_auth_requests/claim", config.api_url()),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    if !response.is_success() {
        eprintln!(
            "The sign-in could not be completed ({}): {}",
            response.status,
            response.error_detail()
        );
        std::process::exit(1);
    }
    auth::login_with_token(config, token_from(&response));
}

fn login_via_device(config: &Config) {
    let client = ApiClient::new(config.api_url().to_string(), None);
    let response = register(
        config,
        &client,
        r#"{"data":{"type":"cli_auth_requests","attributes":{"kind":"device","client":"cli"}}}"#,
    );

    let device_code = match string_attribute(&response, "device_code") {
        Some(code) => zeroize::Zeroizing::new(code),
        None => {
            eprintln!("This Klaay environment does not offer the type-in sign-in.");
            std::process::exit(1);
        }
    };
    let user_code = string_attribute(&response, "user_code").unwrap_or_default();
    let verification_uri = string_attribute(&response, "verification_uri")
        .unwrap_or_else(|| format!("{}/device", resolve_web_url(config, &response)));

    // Only the short code is printed. The device code above is this
    // process's secret and never reaches the screen or the scrollback.
    println!("Open this page in any browser: {verification_uri}");
    println!("Then type this code: {user_code}");
    println!("Waiting for you to finish signing in... (press Ctrl+C to cancel)");

    let body = zeroize::Zeroizing::new(format!(
        r#"{{"data":{{"type":"cli_auth_requests","attributes":{{"device_code":"{}"}}}}}}"#,
        &*device_code
    ));
    auth::login_with_token(config, poll_for_token(config, &client, body.as_bytes()));
}

fn register(config: &Config, client: &ApiClient, body: &str) -> crate::client::ApiResponse {
    let response = client.raw_post(
        &format!("{}/cli_auth_requests", config.api_url()),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    if !response.is_success() {
        eprintln!(
            "Could not start a browser sign-in ({}): {}",
            response.status,
            response.error_detail()
        );
        eprintln!(
            "If this Klaay environment predates the current sign-in support, upgrade the server, or ask an administrator for a token and run `{} login --with-token`.",
            crate::config::bin_name()
        );
        std::process::exit(1);
    }
    // The server says when a path it still serves is on its way out, so the
    // next cut-over needs no guesswork here.
    if let Some(warning) = string_attribute(&response, "deprecation_warning") {
        eprintln!("Warning: {warning}");
    }
    response
}

/// What one claim response tells the poll loop to do next.
#[derive(Debug, PartialEq, Eq)]
enum PollStep {
    /// Registered, nobody has approved it yet.
    Wait,
    /// The token is here.
    Done,
    /// Expired or already claimed - this request is spent.
    Spent,
    /// Transient. Wait a full extra interval, then ask again.
    BackOff,
    /// The server refused in a way waiting cannot fix.
    Fail,
}

/// A rate limit and a server fault are both transient, so both back off. The
/// deadline bounds the wait, so a blip must not end a sign-in the person is
/// part-way through.
fn poll_step(status: u16) -> PollStep {
    match status {
        200 => PollStep::Done,
        202 => PollStep::Wait,
        404 => PollStep::Spent,
        429 => PollStep::BackOff,
        500..=599 => PollStep::BackOff,
        _ => PollStep::Fail,
    }
}

fn poll_for_token(config: &Config, client: &ApiClient, body: &[u8]) -> zeroize::Zeroizing<String> {
    let claim_url = format!("{}/cli_auth_requests/claim", config.api_url());
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            eprintln!("Timed out waiting for the browser sign-in.");
            std::process::exit(1);
        }
        std::thread::sleep(POLL_INTERVAL);

        let response = client.raw_post(&claim_url, &[("Content-Type", "application/json")], body);
        match poll_step(response.status) {
            PollStep::Wait => continue,
            PollStep::Done => return token_from(&response),
            PollStep::Spent => {
                eprintln!(
                    "The sign-in request expired or was already used - run `{} login` again.",
                    crate::config::bin_name()
                );
                std::process::exit(1);
            }
            PollStep::BackOff => {
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            PollStep::Fail => {
                eprintln!(
                    "Sign-in polling failed ({}): {}",
                    response.status,
                    response.error_detail()
                );
                std::process::exit(1);
            }
        }
    }
}

fn token_from(response: &crate::client::ApiResponse) -> zeroize::Zeroizing<String> {
    match string_attribute(response, "token") {
        Some(token) => zeroize::Zeroizing::new(token),
        None => {
            eprintln!("The sign-in completed but the server's response carried no token.");
            std::process::exit(1);
        }
    }
}

fn string_attribute(response: &crate::client::ApiResponse, name: &str) -> Option<String> {
    response
        .body()
        .and_then(|b| b.get("data"))
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get(name))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

/// The deployment announces its own SPA origin, so `--api-url` alone is
/// enough against any Klaay environment - a staging API must not send the
/// user to production's login page. An explicit `--web-url`/`KLAAY_WEB_URL`
/// still wins; the built-in default only applies against older servers that
/// announce nothing.
fn resolve_web_url(config: &Config, response: &crate::client::ApiResponse) -> String {
    let announced =
        string_attribute(response, "web_url").map(|w| w.trim_end_matches('/').to_string());
    match (&announced, config.web_url_explicit()) {
        (Some(announced), false) => {
            // Held to the same transport standard as the configured URLs -
            // the server is trusted for *where* its login page lives, not to
            // downgrade the plaintext policy.
            if let Err(e) = config.check_url_security(announced) {
                eprintln!("The server announced a sign-in page URL that can't be used: {e}");
                std::process::exit(1);
            }
            announced.clone()
        }
        _ => {
            if announced.is_none() && !config.web_url_explicit() {
                eprintln!(
                    "Note: this server doesn't announce its sign-in page; opening {} - pass --web-url if that's the wrong web app for {}.",
                    config.web_url(),
                    config.api_url()
                );
            }
            config.web_url().to_string()
        }
    }
}

/// Serves exactly one request, answers with a page telling the person they
/// can close the tab, and returns the code the browser carried. No HTTP
/// server dependency: one request line is all this has to understand.
fn wait_for_code(listener: TcpListener) -> Option<zeroize::Zeroizing<String>> {
    let stream = listener.incoming().next()?.ok()?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;

    let code = code_from_request_line(&request_line);
    let page = match &code {
        Some(_) => "<!doctype html><meta charset=utf-8><title>Signed in</title><p>You are signed in. You can close this window and go back to your terminal.",
        None => "<!doctype html><meta charset=utf-8><title>Sign-in failed</title><p>That reply carried no sign-in code. Go back to your terminal and run the command again.",
    };
    let stream = reader.get_mut();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.flush();
    code
}

/// Pulls `code` out of `GET /?code=…&… HTTP/1.1`. Percent-decoding is not
/// needed - the server mints a base64url code - but a `+` is decoded because
/// some clients still encode a query that way.
fn code_from_request_line(line: &str) -> Option<zeroize::Zeroizing<String>> {
    let target = line.split_whitespace().nth(1)?;
    let query = target.split_once('?')?.1;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "code")
        .map(|(_, value)| zeroize::Zeroizing::new(value.replace('+', " ")))
        .filter(|code| !code.is_empty())
}

/// 32 random bytes, base64url-encoded - the PKCE verifier. `Zeroizing` like
/// every other credential-shaped value in this crate: it is the only thing
/// standing between a leaked code and a minted token.
fn random_secret() -> zeroize::Zeroizing<String> {
    let mut bytes = [0u8; 32];
    // Unrecoverable: without OS randomness there is no safe secret to offer.
    getrandom::fill(&mut bytes).unwrap_or_else(|e| {
        eprintln!("Could not obtain OS randomness for the sign-in secret: {e}");
        std::process::exit(1);
    });
    zeroize::Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// S256, the only challenge method this flow offers: the server stores this
/// and can prove nothing from it, because a hash cannot be run backwards.
fn challenge_for(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Uses the `open` crate rather than hand-rolled per-OS `Command`
/// invocations - it calls the platform's native launch API (e.g.
/// `ShellExecute` on Windows) directly instead of going through a shell,
/// so URL query characters can't be reinterpreted as shell syntax.
fn open_browser(url: &str) -> bool {
    match open::that(url) {
        Ok(()) => {
            println!("Opening your browser for sign-in...");
            true
        }
        Err(e) => {
            eprintln!("Could not open a browser automatically ({e}).");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The whole security argument lives in this address: a remote attacker
    // cannot receive the sign-in code. This calls the function
    // `login_via_browser` uses, so widening that address fails here.
    #[test]
    fn the_sign_in_listener_is_loopback_only() {
        let addr = bind_loopback().expect("bind").local_addr().expect("addr");
        assert!(addr.ip().is_loopback());
    }

    // A server blip must not end a sign-in the person is part-way through.
    // The deadline bounds the wait, so backing off costs nothing.
    #[test]
    fn a_server_error_backs_off_instead_of_ending_the_sign_in() {
        assert_eq!(poll_step(500), PollStep::BackOff);
        assert_eq!(poll_step(502), PollStep::BackOff);
        assert_eq!(poll_step(503), PollStep::BackOff);
        assert_eq!(poll_step(504), PollStep::BackOff);
    }

    #[test]
    fn poll_step_reads_the_settled_answers() {
        assert_eq!(poll_step(200), PollStep::Done);
        assert_eq!(poll_step(202), PollStep::Wait);
        assert_eq!(poll_step(404), PollStep::Spent);
        assert_eq!(poll_step(429), PollStep::BackOff);
    }

    #[test]
    fn a_client_error_ends_the_sign_in() {
        assert_eq!(poll_step(400), PollStep::Fail);
        assert_eq!(poll_step(403), PollStep::Fail);
    }

    #[test]
    fn random_secret_is_43_base64url_chars() {
        let secret = random_secret();
        assert_eq!(secret.len(), 43);
        assert!(secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    // The one value the server checks against. RFC 7636's own S256 example:
    // verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" hashes to this.
    #[test]
    fn challenge_is_the_rfc_7636_s256_example() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn challenge_carries_no_padding() {
        assert!(!challenge_for("anything").contains('='));
    }

    #[test]
    fn code_comes_out_of_the_request_line() {
        assert_eq!(
            code_from_request_line("GET /?code=abc123 HTTP/1.1\r\n").map(|c| c.to_string()),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn code_is_found_among_other_parameters() {
        assert_eq!(
            code_from_request_line("GET /?state=x&code=abc123&other=y HTTP/1.1\r\n")
                .map(|c| c.to_string()),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn a_reply_with_no_code_yields_none() {
        assert!(code_from_request_line("GET / HTTP/1.1\r\n").is_none());
        assert!(code_from_request_line("GET /?code= HTTP/1.1\r\n").is_none());
        assert!(code_from_request_line("garbage\r\n").is_none());
    }
}
