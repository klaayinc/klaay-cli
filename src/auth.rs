// SPDX-License-Identifier: GPL-3.0-or-later
use crate::client::{ApiClient, HttpMethod};
use crate::config::Config;
use crate::token_store::{self, StoredToken};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;

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

/// Stores the token, downgrading a storage failure to a warning: the login
/// itself succeeded either way, the user just won't stay logged in.
fn save_or_warn(stored: &StoredToken) {
    if let Err(e) = token_store::save(stored) {
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

/// JWT shape check shared by `require_login` (stored tokens) and
/// `login_with_token` (tokens arriving from the sign-in mailbox or stdin):
/// base64url charset and exactly three non-empty dot-separated segments.
/// Anything else is corrupted or not a JWT, and would otherwise reach ureq's
/// header API verbatim inside the `Authorization` value.
fn token_shape_ok(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && parts.len() == 3
        && parts.iter().all(|p| !p.is_empty())
}

/// Kiln ids serialize as JSON numbers, but tolerate strings too rather than
/// silently dropping an id a future serializer renders differently.
fn json_id_string(v: &Value) -> Option<String> {
    v.as_u64()
        .map(|n| n.to_string())
        .or_else(|| v.as_str().map(|s| s.to_string()))
}

/// Completes a login with an already-minted token - from the browser
/// sign-in mailbox (web_login.rs) or `--with-token`. Verifies it against
/// the live API via GET /me before storing, which also confirms the token
/// actually belongs to *this* `--api-url` (a mailbox token minted by one
/// deployment is useless against another).
pub(crate) fn login_with_token(config: &Config, mut token: zeroize::Zeroizing<String>) {
    if !token_shape_ok(&token) {
        eprintln!("That value doesn't look like a Klaay API token.");
        // Owned here, so zeroize the real buffer before the no-unwind exit.
        zeroize::Zeroize::zeroize(&mut *token);
        std::process::exit(1);
    }
    let client = ApiClient::new(config.api_url().to_string(), Some(token.clone()));
    let response = client.call(HttpMethod::Get, "/me", None);
    if !response.is_success() {
        eprintln!(
            "The token was not accepted by {} ({}): {}",
            config.api_url(),
            response.status,
            response.error_detail()
        );
        std::process::exit(1);
    }
    let attributes = response
        .body()
        .and_then(|b| b.get("data"))
        .and_then(|d| d.get("attributes"))
        .cloned()
        .unwrap_or(Value::Null);
    let email = attributes
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let claims = decode_jwt_payload(&token);
    // /me's current_account_id reflects what the server resolved for this
    // token; the JWT claim is the fallback if the response omits it.
    let account_id = attributes
        .get("current_account_id")
        .and_then(json_id_string)
        .or_else(|| claims.get("account_id").and_then(json_id_string));
    let exp = claims.get("exp").and_then(|v| v.as_i64());

    let email_display = email.as_deref().unwrap_or("(unknown email)");
    match exp {
        Some(exp) => println!(
            "Logged in as {email_display}\nToken stored (expires {})",
            format_timestamp(exp)
        ),
        None => println!("Logged in as {email_display}"),
    }
    save_or_warn(&StoredToken {
        token,
        api_url: config.api_url().to_string(),
        account_id,
        email,
    });
}

/// `--with-token`: reads a token from stdin - the fallback when the browser
/// flow can't reach this machine (e.g. over SSH), and the natural path for
/// CI. Echo-off when interactive, plain line read when piped.
pub(crate) fn login_with_stdin_token(config: &Config) {
    use std::io::IsTerminal;
    let token = if std::io::stdin().is_terminal() {
        zeroize::Zeroizing::new(rpassword::prompt_password("Token: ").unwrap_or_else(|e| {
            eprintln!("Could not read token: {e}");
            std::process::exit(1);
        }))
    } else {
        let mut line = zeroize::Zeroizing::new(String::new());
        if let Err(e) = std::io::stdin().read_line(&mut line) {
            eprintln!("Could not read token from stdin: {e}");
            std::process::exit(1);
        }
        // The trimmed copy becomes the protected token; `line` (which may
        // still carry the trailing newline) zeroizes on drop.
        zeroize::Zeroizing::new(line.trim().to_string())
    };
    if token.is_empty() {
        eprintln!("Token cannot be empty.");
        std::process::exit(1);
    }
    login_with_token(config, token);
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
    if !token_shape_ok(&stored.token) {
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
