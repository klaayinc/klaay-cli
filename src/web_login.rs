use crate::auth;
use crate::client::ApiClient;
use crate::config::Config;
use base64::Engine;
use std::time::{Duration, Instant};

// Browser sign-in via the server-side nonce mailbox (kiln's
// /cli_auth_requests endpoints), the device-authorization-grant shape and
// the same pattern KlaayGuard's `?app=...&state=...` login flow uses: this
// process never talks to an identity provider and needs no OAuth client
// registration. It registers a single-use nonce, opens the normal Klaay
// login page in the browser (which supports every sign-in method the
// deployment has), and polls until the signed-in user approves the CLI -
// at which point the server mints the long-lived `client: "cli"` token
// into the mailbox for exactly one retrieval. Works even when the browser
// runs on a different machine than this process (e.g. over SSH), since
// the handoff goes through the server, not a loopback port.

/// Matches the server's CliAuthRequest::TTL (5 minutes) plus slack: the
/// normal end is the server answering 404 once the request expires, this
/// deadline is only the local backstop if that never arrives.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(360);
/// Well under the claim endpoint's 60/minute rate-limit bucket.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

pub(crate) fn login_via_browser(config: &Config) {
    let nonce = random_nonce();
    let client = ApiClient::new(config.api_url().to_string(), None);
    let body = mailbox_body(&nonce);

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
            "If this Klaay environment predates CLI sign-in support, use `{} login --email` instead.",
            crate::config::bin_name()
        );
        std::process::exit(1);
    }

    // The deployment announces its own SPA origin in the register response,
    // so --api-url alone is sufficient against any Klaay environment - a
    // staging API must not send the user to production's login page. An
    // explicit --web-url/KLAAY_WEB_URL still wins; the built-in default only
    // applies against older servers that don't announce one.
    let server_web_url = response
        .body()
        .and_then(|b| b.get("data"))
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get("web_url"))
        .and_then(|w| w.as_str())
        .map(|w| w.trim_end_matches('/').to_string());
    let web_url = match (&server_web_url, config.web_url_explicit()) {
        (Some(announced), false) => {
            // Held to the same transport standard as the configured URLs -
            // the server is trusted for *where* its login page lives, not to
            // downgrade the plaintext policy.
            if let Err(e) = config.check_url_security(announced) {
                eprintln!("The server announced a sign-in page URL that can't be used: {e}");
                std::process::exit(1);
            }
            announced.as_str()
        }
        _ => config.web_url(),
    };
    if server_web_url.is_none() && !config.web_url_explicit() {
        // Older server: it accepted the request but can't say where its web
        // app lives, so the built-in default is a guess worth flagging.
        eprintln!(
            "Note: this server doesn't announce its sign-in page; opening {web_url} - pass --web-url if that's the wrong web app for {}.",
            config.api_url()
        );
    }

    // The nonce is base64url (verified by construction in `random_nonce`),
    // so embedding it in a query string needs no percent-encoding.
    let url = format!("{}/login?app=cli&state={}", web_url, &*nonce);
    open_browser(&url);
    // The first segment doubles as a phishing check: the consent page shows
    // the same code, so the user can confirm the approval they're looking at
    // belongs to this terminal. Only 6 of 22 chars - the remaining 16 keep
    // ~96 bits of entropy out of terminal scrollback.
    // Char-based, not a byte slice - can't panic on a boundary, and unlike a
    // `get(..6).unwrap_or(&nonce)` fallback it can never print the whole
    // nonce (the mailbox's bearer secret) to the terminal.
    let verification_code: String = nonce.chars().take(6).collect();
    println!("Verification code: {verification_code}");
    println!("Waiting for you to finish signing in... (press Ctrl+C to cancel)");

    let claim_url = format!("{}/cli_auth_requests/claim", config.api_url());
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    let token = loop {
        if Instant::now() >= deadline {
            eprintln!("Timed out waiting for the browser sign-in.");
            std::process::exit(1);
        }
        std::thread::sleep(POLL_INTERVAL);

        let response = client.raw_post(
            &claim_url,
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        );
        match response.status {
            // Registered but not yet approved - keep waiting.
            202 => continue,
            200 => {
                let token = response
                    .body()
                    .and_then(|b| b.get("data"))
                    .and_then(|d| d.get("attributes"))
                    .and_then(|a| a.get("token"))
                    .and_then(|t| t.as_str())
                    .map(|t| zeroize::Zeroizing::new(t.to_string()));
                match token {
                    Some(token) => break token,
                    None => {
                        eprintln!(
                            "The sign-in completed but the server's response carried no token."
                        );
                        std::process::exit(1);
                    }
                }
            }
            // The request expired or was already claimed - either way this
            // nonce is spent.
            404 => {
                eprintln!(
                    "The sign-in request expired or was already used - run `{} login` again.",
                    crate::config::bin_name()
                );
                std::process::exit(1);
            }
            // Rate-limited: back off a full extra interval and retry rather
            // than failing a sign-in the user is mid-way through.
            429 => {
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            status => {
                eprintln!(
                    "Sign-in polling failed ({status}): {}",
                    response.error_detail()
                );
                std::process::exit(1);
            }
        }
    };

    auth::login_with_token(config, token);
}

/// 16 random bytes, base64url-encoded to 22 characters - the mailbox's
/// bearer secret. `Zeroizing` like every other credential-shaped value in
/// this crate: anyone holding the nonce can claim the minted token during
/// the request's 5-minute lifetime.
fn random_nonce() -> zeroize::Zeroizing<String> {
    let mut bytes = [0u8; 16];
    // Unrecoverable: without OS randomness there is no safe nonce to offer.
    getrandom::fill(&mut bytes).unwrap_or_else(|e| {
        eprintln!("Could not obtain OS randomness for the sign-in nonce: {e}");
        std::process::exit(1);
    });
    zeroize::Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// The register and claim bodies are identical: the nonce is the only
/// parameter either endpoint takes. Hand-built (mirroring auth.rs's
/// `build_secret_auth_body` convention for credential-carrying bodies)
/// rather than routed through a `serde_json::Value` the nonce would sit in
/// unzeroized; safe to embed verbatim since the nonce is base64url by
/// construction - no JSON-special characters.
fn mailbox_body(nonce: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(format!(
        r#"{{"data":{{"type":"cli_auth_requests","attributes":{{"nonce":"{nonce}"}}}}}}"#
    ))
}

/// Uses the `open` crate rather than hand-rolled per-OS `Command`
/// invocations - it calls the platform's native launch API (e.g.
/// `ShellExecute` on Windows) directly instead of going through a shell,
/// so URL query characters can't be reinterpreted as shell syntax.
fn open_browser(url: &str) {
    match open::that(url) {
        // Doesn't print `url` on success - it carries the nonce in its query
        // string, which the user doesn't need to see (the browser already
        // has it) and shouldn't end up in terminal scrollback or CI log
        // captures. The failure branch below still has to print it - the
        // user needs the full URL to open it manually.
        Ok(()) => println!("Opening your browser for sign-in..."),
        Err(e) => {
            eprintln!("Could not open a browser automatically ({e}).");
            eprintln!("Please open the following URL manually: {url}");
            eprintln!(
                "Warning: this URL contains a single-use sign-in secret. If it appears in logs or shared terminal history, press Ctrl+C and re-run to get a fresh one."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_nonce_is_22_base64url_chars() {
        let nonce = random_nonce();
        assert_eq!(nonce.len(), 22);
        assert!(nonce
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn mailbox_body_is_valid_json_with_the_nonce() {
        let body = mailbox_body("abcDEF123-_x");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(
            parsed
                .get("data")
                .and_then(|d| d.get("attributes"))
                .and_then(|a| a.get("nonce"))
                .and_then(|n| n.as_str()),
            Some("abcDEF123-_x")
        );
    }
}
