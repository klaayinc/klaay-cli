use std::path::PathBuf;

// `pub(crate)`, not module-private - `main.rs`'s `--api-url` help text
// interpolates this same value at runtime (via clap's `help = EXPR` support,
// not a `///` doc comment, since `concat!` can't embed a named `const` - only
// literals) so the two can never silently drift apart the way a second,
// independently-typed literal would.
pub(crate) const DEFAULT_API_URL: &str = "https://api.klaay.com";
// The web app origin hosting the login page the browser sign-in flow opens
// (see web_login.rs). Matches kiln's own default for its SPA origin
// (config/initializers/cors.rb).
pub(crate) const DEFAULT_WEB_URL: &str = "https://app.klaay.com";

/// The invoked binary's own name, for "run `<this> ...`" hints. Lives here (a
/// foundational module) rather than in `schema`/`client` so any layer can use
/// it without an upward dependency. Computed once and cached.
pub(crate) fn bin_name() -> &'static str {
    static BIN_NAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        // `args_os()`, not `args()` - `args()` panics on a non-UTF-8 argv[0];
        // `args_os()` lets it fall through to the `.to_str()` -> `None`
        // fallback below.
        std::env::args_os()
            .next()
            .and_then(|p| {
                // `file_stem`, not `file_name` - strips the `.exe` on Windows so
                // hints read `klaay resources`, not `klaay.exe resources`. A
                // no-op on Unix, where the binary has no extension.
                std::path::Path::new(&p)
                    .file_stem()
                    .and_then(|f| f.to_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| env!("CARGO_BIN_NAME").to_string())
    });
    &BIN_NAME
}

#[derive(Debug, PartialEq)]
pub(crate) struct Config {
    // Private - `resolve()` is the only way to construct a `Config`, so this
    // is the only value any caller can ever see, guaranteeing every consumer
    // observes the normalized, already-`enforce_secure`-checked form
    // rather than a mutated one that bypassed both.
    api_url: String,
    // The web app origin for browser sign-in; resolved and normalized the
    // same way as `api_url`.
    web_url: String,
    // Stored (not just consumed locally by `enforce_secure`) so other
    // insecure-transport decisions - e.g. upload.rs's plaintext-upload-URL
    // check - can reuse the same opt-in instead of inventing a second,
    // differently-named flag/env var for what is the same underlying user
    // intent ("I know this isn't HTTPS and I accept that").
    force_insecure: bool,
}

impl Config {
    /// Resolution order: --api-url flag, then KLAAY_API_URL env var, then the
    /// default. `force_insecure` (from `--force-insecure` or
    /// `KLAAY_ALLOW_INSECURE`) downgrades `enforce_secure`'s hard error for a
    /// non-loopback, non-HTTPS URL back to a warning - see that function.
    ///
    /// Returns `Result` rather than exiting internally - the caller (`main`)
    /// prints and exits on `Err`, the same contract every other fallible
    /// entry point in this crate already uses (`schema::fetch_spec`,
    /// `schema::describe`), and the reason this whole function is
    /// integration-testable rather than only its extracted pure helpers.
    pub(crate) fn resolve(
        api_url_flag: Option<String>,
        web_url_flag: Option<String>,
        force_insecure: bool,
    ) -> Result<Self, String> {
        let api_url = api_url_flag
            .or_else(|| match std::env::var("KLAAY_API_URL") {
                Ok(v) => Some(v),
                // Expected, silent case - the env var simply isn't set.
                Err(std::env::VarError::NotPresent) => None,
                // Distinct from the above: the var *is* set, but to a value
                // that isn't valid UTF-8 - a real configuration mistake, not
                // "unset". Falling back to the default here without saying
                // so would otherwise silently point the CLI at production
                // instead of whatever environment the user actually meant.
                Err(std::env::VarError::NotUnicode(v)) => {
                    // Names the actual fallback URL, not just "the default" -
                    // without it, a user who set KLAAY_API_URL to point at a
                    // staging/dev environment by mistake (a non-UTF-8 value)
                    // has no immediate way to tell they've silently landed on
                    // production instead, short of separately checking
                    // DEFAULT_API_URL's value in the source.
                    eprintln!(
                        "Warning: KLAAY_API_URL contains non-UTF-8 bytes ({v:?}) - ignoring it and using the default ({DEFAULT_API_URL})."
                    );
                    None
                }
            })
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());
        // Normalized once, here, so every consumer (token_store.rs's
        // keyring/file keys, client.rs's URL building, auth.rs's request
        // construction) sees the same canonical form - otherwise
        // `https://api.example.com` and `https://api.example.com/` would be
        // treated as different environments, silently splitting a single
        // user's stored token across two keyring/file entries depending on
        // which form they happened to type. `trim_end_matches` strips *all*
        // consecutive trailing slashes, not just one - `https://api.example.
        // com///` is normalized down to `https://api.example.com` the same
        // way, with no separate warning for the unusual multi-slash input.
        let api_url = api_url.trim_end_matches('/').to_string();
        // Same flag -> env -> default resolution and normalization as
        // `api_url` above; the browser sign-in URL is built from this.
        let web_url = web_url_flag
            .or_else(|| match std::env::var("KLAAY_WEB_URL") {
                Ok(v) => Some(v),
                Err(std::env::VarError::NotPresent) => None,
                Err(std::env::VarError::NotUnicode(v)) => {
                    eprintln!(
                        "Warning: KLAAY_WEB_URL contains non-UTF-8 bytes ({v:?}) - ignoring it and using the default ({DEFAULT_WEB_URL})."
                    );
                    None
                }
            })
            .unwrap_or_else(|| DEFAULT_WEB_URL.to_string());
        let web_url = web_url.trim_end_matches('/').to_string();
        // Either the flag or the env var opts in - a script/CI pipeline that
        // can't easily pass a flag can still set the env var, same pattern
        // as KLAAY_API_URL above. Checked against a specific truthy value,
        // not `.is_ok()` - the latter would treat *any* set value, including
        // an accidentally-exported empty string (`KLAAY_ALLOW_INSECURE=`),
        // as opting in, silently downgrading a hard error to a warning. This
        // also matches the documented contract (the error message below, and
        // main.rs's --force-insecure help text, both say "=1 (or =true /
        // =yes)"). Compared case-insensitively - some CI systems normalize
        // env var values to upper/title case (`TRUE`, `YES`, `True`), and a
        // user who set one of those expecting it to work would otherwise see
        // the opt-in silently fail with no indication why.
        // `NotUnicode` handled explicitly, same as `KLAAY_API_URL` above -
        // without this, a value with non-UTF-8 bytes would silently fall
        // through `.map()` (which only ever runs on `Ok`) straight to
        // `false`, and the user would hit the hard `process::exit(1)` in
        // `block_or_warn` below with no indication their env var was ever
        // read, let alone why it didn't take effect.
        // The raw (not-yet-lowercased) value is kept alongside the lowercased
        // one used for matching below - the warning has to show what the
        // user actually typed (e.g. `KLAAY_ALLOW_INSECURE=ON`), not the
        // normalized form it gets compared against, or the message would
        // silently substitute a value they never set.
        let allow_insecure_env_raw = match std::env::var("KLAAY_ALLOW_INSECURE") {
            Ok(v) => Some(v),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(v)) => {
                eprintln!(
                    "Warning: KLAAY_ALLOW_INSECURE contains non-UTF-8 bytes ({v:?}) - ignoring it."
                );
                None
            }
        };
        let allow_insecure_env_lower = allow_insecure_env_raw
            .as_deref()
            .map(str::to_ascii_lowercase);
        // A non-empty value that isn't one of the recognized truthy strings
        // is warned about, not silently treated as `false` - without this, a
        // user who sets e.g. `KLAAY_ALLOW_INSECURE=on` (a common truthy
        // convention elsewhere, but not one this CLI accepts) would see only
        // the hard `process::exit(1)` from `block_or_warn` below, with no
        // indication their env var was read at all, let alone why it didn't
        // take effect.
        //
        // Printed unconditionally here, regardless of the current URL's
        // verdict - an earlier version deferred this into `block_or_warn`
        // (only printed for a `PlaintextRisk` URL), reasoning that warning
        // about it against a `Safe` URL would be misleading since the value
        // has no effect *this run*. But the env var's value is genuinely
        // invalid regardless of today's URL - deferring the warning meant a
        // user (or a teammate who inherited their shell config) could carry
        // a broken `KLAAY_ALLOW_INSECURE` for months without ever seeing
        // this warning, only discovering it's not recognized at the exact
        // moment they hit a plaintext-risk URL and need it to actually work.
        let unrecognized_allow_insecure_value: Option<&str> = match &allow_insecure_env_lower {
            Some(v) if !v.is_empty() && !matches!(v.as_str(), "1" | "true" | "yes") => {
                allow_insecure_env_raw.as_deref()
            }
            _ => None,
        };
        if let Some(v) = unrecognized_allow_insecure_value {
            // Notes when `--force-insecure` already covers this run, rather
            // than fully suppressing the warning in that case (an earlier
            // draft of this fix did) - a user who always passes
            // `--force-insecure` (e.g. baked into a wrapper script) would
            // otherwise never learn their env var is broken, and if they
            // ever drop the flag expecting the env var to still cover them,
            // they'd hit the exact silent-until-it-matters problem this
            // unconditional warning exists to prevent in the first place.
            let flag_note = if force_insecure {
                " (--force-insecure is already covering this run, but the env var is still worth fixing)"
            } else {
                ""
            };
            eprintln!(
                "Warning: KLAAY_ALLOW_INSECURE={v} is not a recognized value (use \"1\", \"true\", or \"yes\") - ignoring it{flag_note}."
            );
        }
        // Named distinctly from the `force_insecure` parameter above (not
        // shadowed under the same name) - a reader could otherwise mistake
        // which value actually ends up in the `Config` struct without
        // tracing that this `let` rebinds the parameter rather than
        // computing something separate from it.
        let effective_force_insecure = force_insecure
            || matches!(
                allow_insecure_env_lower.as_deref(),
                Some("1" | "true" | "yes")
            );
        // Each URL's failure names the flag/env pair it came from - the two
        // share one classifier, and without the label a bad --web-url would
        // print a message indistinguishable from a bad --api-url.
        enforce_secure(&api_url, effective_force_insecure)
            .map_err(|e| format!("--api-url / KLAAY_API_URL: {e}"))?;
        // The web URL opens in a browser rather than carrying credentials
        // from this process, but a plaintext non-loopback login page is the
        // same class of mistake - hold it to the same standard.
        enforce_secure(&web_url, effective_force_insecure)
            .map_err(|e| format!("--web-url / KLAAY_WEB_URL: {e}"))?;
        Ok(Config {
            api_url,
            web_url,
            force_insecure: effective_force_insecure,
        })
    }

    pub(crate) fn api_url(&self) -> &str {
        &self.api_url
    }

    pub(crate) fn web_url(&self) -> &str {
        &self.web_url
    }

    /// Whether the user opted into insecure (non-HTTPS, non-loopback)
    /// transport via `--force-insecure`/`KLAAY_ALLOW_INSECURE` - reused by
    /// upload.rs to decide whether a plaintext `http://` direct-upload URL
    /// should be a hard error or just a warning, the same standard already
    /// applied to the API base URL itself.
    pub(crate) fn force_insecure(&self) -> bool {
        self.force_insecure
    }
}

/// The result of classifying an `--api-url` value: a non-loopback `http://`
/// host or a scheme that's neither `http` nor `https` is a real
/// credential-leak risk (`PlaintextRisk`) since it would send real
/// credentials or an SSO id-token in plain text; `http://localhost`/
/// `127.0.0.1` against a local dev server is an intentional, documented use
/// case and is `Safe`. A missing host, an unparseable URL, or a non-http(s)
/// scheme isn't a credential-leak risk (there's nowhere for the request to
/// go, or `--force-insecure` couldn't help it succeed anyway), but it's a
/// hard error regardless of `allow_insecure` - a `UrlProblem` URL can never
/// produce a working request, so `enforce_secure` fails fast on it rather
/// than letting `Config::resolve` succeed with a URL that's guaranteed to
/// fail later, at a far less clear point (a plain network error from
/// `client.rs`'s string-concatenated request URLs) than this upfront,
/// descriptive message.
///
/// Split out from `enforce_secure` into its own pure function specifically
/// so this classification logic is unit testable without capturing stderr or
/// spawning a subprocess to observe `process::exit`.
///
/// Named `Safe`, not `Ok` - the latter would shadow `std::result::Result::Ok`
/// right next to it (`classify_api_url`'s very first line matches a real
/// `Result`'s `Ok(parsed)`), forcing readers to disambiguate two
/// structurally identical identifiers with different meanings.
#[derive(Debug, PartialEq, Eq)]
enum UrlVerdict {
    Safe,
    UrlProblem(String),
    PlaintextRisk(String),
}

/// Parses the URL properly (via a direct `url` dependency, not just oauth2's
/// re-export - see Cargo.toml) and compares the host exactly, rather than a
/// `starts_with` prefix check a hostname like `localhost.evil.com` could slip
/// past.
fn classify_api_url(api_url: &str) -> UrlVerdict {
    let Ok(parsed) = url::Url::parse(api_url) else {
        return UrlVerdict::UrlProblem(format!(
            "{api_url} is not a valid URL - requests will likely fail."
        ));
    };
    match parsed.scheme() {
        "https" => UrlVerdict::Safe,
        // No separate "hostless http" branch here - confirmed empirically
        // (a battery of candidate URLs, not just the two forms an earlier
        // version of this code cited) that the `url` crate never returns
        // `Ok` with `host_str() == None` for the "http" special scheme: a
        // truly missing host (`http://`, `http:///`, `http://:8080/path`,
        // etc.) always fails to parse at all ("empty host", the `Err` arm
        // above), and a form like `http:///path` that looks hostless instead
        // parses with `host_str() == Some("path")`. A dead branch here was
        // previously left in place (and its intended test accidentally only
        // re-tested the `Err` arm) - removed rather than kept as
        // unreachable/untested defensive code.
        "http" if is_loopback_host(parsed.host()) => UrlVerdict::Safe,
        "http" => UrlVerdict::PlaintextRisk(format!(
            "{api_url} is not HTTPS - sign-in credentials would travel to it in plain text."
        )),
        // `UrlProblem`, not `PlaintextRisk` - a `PlaintextRisk` verdict
        // implies `--force-insecure`/`KLAAY_ALLOW_INSECURE` can make the URL
        // usable, but that's not true for a non-http(s) scheme: `client.rs`'s
        // `raw_post`/`raw_put` both hard-reject (`process::exit(1)`) any URL
        // that isn't `http://`/`https://`, unconditionally, with no opt-in of
        // their own. Blocking here behind an opt-in that can't actually
        // unblock anything downstream would just dangle a false promise -
        // the request always fails either way, just one step later with a
        // more confusing message. Not categorized per-scheme (`ftp`/`ws` vs.
        // `file`/`data`) either, since that split doesn't matter once this is
        // `UrlProblem`: every non-http(s) scheme is equally unusable here,
        // regardless of whether it implies real network transport.
        other => UrlVerdict::UrlProblem(format!(
            "{api_url} uses the \"{other}\" scheme - only http and https are supported."
        )),
    }
}

/// Blocks (unless `allow_insecure`) or warns based on `classify_api_url`'s
/// verdict - see that function's doc comment for what each verdict means.
/// Returns `Result` rather than calling `process::exit` itself - matches
/// `schema::fetch_spec`/`schema::describe`'s pattern of surfacing a fatal
/// condition as an `Err` for the caller (ultimately `main`) to print and
/// exit on, which is what actually makes `Config::resolve` itself
/// integration-testable: a test can call it and match on the `Result`
/// instead of needing to capture stderr or spawn a subprocess to observe a
/// `process::exit` call.
fn enforce_secure(api_url: &str, allow_insecure: bool) -> Result<(), String> {
    match classify_api_url(api_url) {
        UrlVerdict::Safe => Ok(()),
        UrlVerdict::UrlProblem(message) => Err(message),
        UrlVerdict::PlaintextRisk(message) => block_or_warn(allow_insecure, &message),
    }
}

fn block_or_warn(allow_insecure: bool, message: &str) -> Result<(), String> {
    if allow_insecure {
        eprintln!("Warning: {message}");
        Ok(())
    } else {
        Err(format!(
            "{message}\nPass --force-insecure or set KLAAY_ALLOW_INSECURE=1 (or =true / =yes) if this is intentional."
        ))
    }
}

/// Matches on `url::Host`'s typed enum rather than parsing `host_str()`'s
/// raw string - `Host::Ipv4`/`Host::Ipv6` already carry a real `Ipv4Addr`/
/// `Ipv6Addr`, so this asks the address directly whether it's loopback
/// (handling every valid representation, e.g. `127.0.0.2`,
/// `0:0:0:0:0:0:0:1`, uniformly) without needing to strip IPv6's `[...]`
/// brackets by hand first or rely on `host_str()`'s bracket-preservation
/// behavior (which, while empirically confirmed correct in this crate's
/// pinned `url` version, isn't part of its documented semver contract the
/// way the typed `Host` enum is). Extracted from `enforce_secure`
/// specifically so it's unit-testable on its own, without needing to
/// capture stderr.
fn is_loopback_host(host: Option<url::Host<&str>>) -> bool {
    match host {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        Some(url::Host::Domain(name)) => {
            // The trailing dot is stripped first - `localhost.` (the
            // canonical FQDN form, RFC 1035) is a real, valid way to write
            // the same hostname - without stripping it first, that form
            // would be misclassified as a non-loopback host and incorrectly
            // hard-error or warn despite resolving to loopback on most
            // systems.
            //
            // `eq_ignore_ascii_case`, not a literal match - RFC 6761
            // specifies "localhost" is case-insensitive, so `--api-url
            // http://LOCALHOST` (a user typo, not a different host)
            // shouldn't fail this check and trigger a false
            // plaintext-credentials warning. Avoids allocating a lowercased
            // copy just to compare it, unlike `to_ascii_lowercase()`.
            name.strip_suffix('.')
                .unwrap_or(name)
                .eq_ignore_ascii_case("localhost")
        }
        None => false,
    }
}

/// Computes the config directory path with no side effects, and no opinion
/// on whether a missing home directory is fatal - that's left to each
/// caller, since a read-only check (e.g. "does the spec cache exist?")
/// might reasonably want to just treat it as "no cache", while writing a
/// token is fatal without it. Callers that only need to read an existing
/// path shouldn't have a directory silently created on disk either -
/// writers call `fs::create_dir_all` themselves.
///
/// Uses `dirs::config_dir()` (not `dirs::home_dir().join(".config")`) so
/// this actually resolves to the right place per platform: `~/.config` via
/// `XDG_CONFIG_HOME` on Linux, `~/Library/Application Support` on macOS, and
/// `%APPDATA%` on Windows - the previous hardcoded `.config` join was a
/// Unix-specific path that also happened to work on macOS by coincidence,
/// but was flatly wrong on Windows (`%USERPROFILE%\.config`, bypassing
/// `%APPDATA%` entirely).
pub(crate) fn config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("klaay"))
}

/// Deliberately not a `Config` method, and deliberately doesn't take
/// `api_url` - this one path is shared across every environment a user has
/// ever logged into, by design, since it's a *map* keyed by `api_url`
/// internally (`token_store.rs`'s file-fallback format), not a
/// per-environment file. Don't assume this needs to change if `Config`
/// grows more fields - only the keyring path (`token_store.rs`'s
/// `keyring_entry`) is genuinely per-`api_url`.
pub(crate) fn credentials_fallback_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("credentials.json"))
}

/// The OpenAPI spec is cached to this one shared path regardless of which
/// `api_url` is active - but unlike a stale comment that used to live here,
/// this doesn't mean switching environments silently serves old data:
/// `schema::fetch_spec` embeds the `api_url` it fetched the spec from inside
/// the cached JSON itself, and re-fetches whenever the currently active
/// `api_url` doesn't match what's stored there. So the path itself is
/// shared, but the content is still correctly invalidated per environment.
pub(crate) fn openapi_cache_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("openapi-cache.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses `url_str` and asserts `is_loopback_host` on its `.host()` -
    /// exercises the same path `classify_api_url` actually takes (a real
    /// parsed `Url`'s typed `Host`), rather than hand-constructing `Host`
    /// variants, and doubles as coverage that the `url` crate itself parses
    /// each input the way these tests assume.
    fn assert_loopback(url_str: &str, expected: bool) {
        let parsed = url::Url::parse(url_str).expect("valid URL");
        assert_eq!(is_loopback_host(parsed.host()), expected, "{url_str}");
    }

    #[test]
    fn recognizes_localhost_hostname() {
        assert_loopback("http://localhost", true);
    }

    #[test]
    fn recognizes_localhost_hostname_case_insensitively() {
        assert_loopback("http://LOCALHOST", true);
        assert_loopback("http://Localhost", true);
    }

    #[test]
    fn recognizes_localhost_trailing_dot_fqdn_form() {
        assert_loopback("http://localhost.", true);
        assert_loopback("http://LOCALHOST.", true);
    }

    #[test]
    fn recognizes_ipv4_loopback() {
        assert_loopback("http://127.0.0.1", true);
        // The whole 127.0.0.0/8 range is loopback, not just 127.0.0.1.
        assert_loopback("http://127.0.0.2", true);
    }

    #[test]
    fn recognizes_ipv6_loopback_bracketed_form() {
        assert_loopback("http://[::1]:3000", true);
    }

    #[test]
    fn recognizes_ipv6_loopback_non_canonical_form() {
        assert_loopback("http://[0:0:0:0:0:0:0:1]", true);
    }

    #[test]
    fn rejects_double_bracketed_ipv6_malformed_host() {
        // `[[::1]]` isn't a valid host per the WHATWG URL spec at all, so
        // this fails to parse rather than reaching `is_loopback_host` -
        // confirming the malformed form can never masquerade as loopback,
        // now structurally guaranteed by `url::Url::parse` itself rather
        // than by hand-rolled bracket-stripping logic.
        assert!(url::Url::parse("http://[[::1]]:3000").is_err());
    }

    #[test]
    fn rejects_non_loopback_hostname() {
        assert_loopback("http://example.com", false);
        assert_loopback("http://localhost.evil.com", false);
    }

    #[test]
    fn rejects_non_loopback_ip() {
        assert_loopback("http://8.8.8.8", false);
        assert_loopback("http://[fc00::1]", false);
    }

    #[test]
    fn rejects_missing_host() {
        assert!(!is_loopback_host(None));
    }

    #[test]
    fn https_url_is_ok() {
        assert_eq!(classify_api_url("https://api.klaay.com"), UrlVerdict::Safe);
    }

    #[test]
    fn default_api_url_is_safe() {
        // Pins the invariant to `DEFAULT_API_URL` itself, not the literal
        // above - that test would still pass even if the constant were
        // changed to a non-HTTPS form, since it never reads the constant.
        assert_eq!(classify_api_url(DEFAULT_API_URL), UrlVerdict::Safe);
    }

    #[test]
    fn loopback_http_url_is_ok() {
        assert_eq!(classify_api_url("http://localhost:3000"), UrlVerdict::Safe);
        assert_eq!(classify_api_url("http://127.0.0.1:3000"), UrlVerdict::Safe);
        // FQDN trailing-dot form, exercised end-to-end through
        // `classify_api_url` (not just the lower-level `is_loopback_host`
        // unit test) - `url::Url::host_str()` preserves the dot verbatim, so
        // a regression in how `is_loopback_host` strips it before comparing
        // would otherwise only be caught by that lower-level test, not the
        // full classification pipeline this CLI actually calls.
        assert_eq!(classify_api_url("http://localhost.:3000"), UrlVerdict::Safe);
    }

    #[test]
    fn non_loopback_http_url_is_plaintext_risk() {
        assert!(matches!(
            classify_api_url("http://api.klaay.com"),
            UrlVerdict::PlaintextRisk(_)
        ));
    }

    #[test]
    fn non_http_scheme_is_url_problem() {
        assert!(matches!(
            classify_api_url("ftp://api.klaay.com"),
            UrlVerdict::UrlProblem(_)
        ));
    }

    #[test]
    fn unparseable_url_is_url_problem() {
        assert!(matches!(
            classify_api_url("not a url"),
            UrlVerdict::UrlProblem(_)
        ));
    }

    /// A truly empty host (`http://`, and every other form tried in
    /// `classify_api_url`'s doc comment) fails to parse at all rather than
    /// producing `Ok` with `host_str() == None` - this is the same `Err(_)`
    /// path as `unparseable_url_is_url_problem` above, kept as a second,
    /// named case specifically because this exact input was the motivating
    /// example for a since-removed dead branch, so a regression that made
    /// `http://` parse successfully again wouldn't silently reopen it.
    #[test]
    fn empty_host_http_url_fails_to_parse_is_url_problem() {
        assert!(matches!(
            classify_api_url("http://"),
            UrlVerdict::UrlProblem(_)
        ));
    }

    // The tests below exercise `Config::resolve` itself, not just its
    // extracted pure helpers - possible now that it returns `Result` instead
    // of calling `process::exit`. Every one of them is marked `#[serial(
    // config_env_vars)]` and shares that same key: `resolve` unconditionally
    // reads `KLAAY_ALLOW_INSECURE` on every call (only `KLAAY_API_URL` is
    // skipped when `api_url_flag` is `Some(...)`, via `.or_else`'s laziness) -
    // its *value* just doesn't change these tests' outcome when `force_
    // insecure` is passed explicitly as `true`, or when the URL is `Safe`
    // (`block_or_warn` is never reached either way). Without `#[serial]`,
    // `cargo test`'s default concurrent execution could let one test's
    // env var mutation race another test's read of the same process-global
    // variable.
    //
    // Each test scopes its env var mutation with `temp_env::with_var` rather
    // than raw `std::env::set_var`/`remove_var` calls: it restores whatever
    // value (or absence) the variable had *before* the test ran once the
    // closure returns - including when the closure panics - rather than
    // unconditionally leaving it removed, which matters if a developer's own
    // shell happens to export `KLAAY_ALLOW_INSECURE` while running `cargo
    // test` locally.

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_accepts_a_safe_https_url() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", None::<&str>),
            ],
            || {
                let config =
                    Config::resolve(Some("https://api.klaay.com".to_string()), None, false)
                        .expect("an https URL should resolve without error");
                assert_eq!(config.api_url(), "https://api.klaay.com");
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_rejects_an_unparseable_url_regardless_of_force_insecure() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", None::<&str>),
            ],
            || {
                // `UrlProblem`, not `PlaintextRisk` - a URL that can never
                // produce a working request must fail fast even with
                // `--force-insecure`, which only exists to unblock a genuine
                // plaintext-transport tradeoff, not a structurally broken URL.
                assert!(Config::resolve(Some("not a valid url".to_string()), None, true).is_err());
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_rejects_a_non_http_scheme_regardless_of_force_insecure() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", None::<&str>),
            ],
            || {
                assert!(
                    Config::resolve(Some("ftp://api.klaay.com".to_string()), None, true).is_err()
                );
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_rejects_a_plaintext_url_without_force_insecure() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", None::<&str>),
            ],
            || {
                assert!(
                    Config::resolve(Some("http://example.com".to_string()), None, false).is_err()
                );
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_accepts_a_plaintext_url_with_force_insecure() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", None::<&str>),
            ],
            || {
                assert!(
                    Config::resolve(Some("http://example.com".to_string()), None, true).is_ok()
                );
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_defaults_web_url_and_normalizes_a_flag_override() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", None::<&str>),
            ],
            || {
                let config =
                    Config::resolve(Some("https://api.klaay.com".to_string()), None, false)
                        .expect("resolves");
                assert_eq!(config.web_url(), DEFAULT_WEB_URL);

                let config = Config::resolve(
                    Some("https://api.klaay.com".to_string()),
                    Some("https://web.example.com///".to_string()),
                    false,
                )
                .expect("resolves");
                assert_eq!(config.web_url(), "https://web.example.com");
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_falls_back_to_klaay_web_url_env_var_when_flag_is_none() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", Some("https://web.env.example.com/")),
            ],
            || {
                let config =
                    Config::resolve(Some("https://api.klaay.com".to_string()), None, false)
                        .expect("resolves");
                assert_eq!(config.web_url(), "https://web.env.example.com");
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_rejects_a_plaintext_web_url_and_names_the_web_flag() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", None::<&str>),
                ("KLAAY_WEB_URL", None::<&str>),
            ],
            || {
                let err = Config::resolve(
                    Some("https://api.klaay.com".to_string()),
                    Some("http://web.example.com".to_string()),
                    false,
                )
                .expect_err("plaintext web url must be rejected");
                assert!(
                    err.contains("--web-url"),
                    "error should name the web flag: {err}"
                );
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_falls_back_to_klaay_api_url_env_var_when_flag_is_none() {
        // Wraps `KLAAY_ALLOW_INSECURE` too (forced to absent), not just
        // `KLAAY_API_URL` - `Config::resolve` unconditionally reads
        // `KLAAY_ALLOW_INSECURE` on every call (only `KLAAY_API_URL` is
        // skipped via `.or_else`'s laziness when the flag is `Some`), so
        // without this a developer's shell happening to export
        // `KLAAY_ALLOW_INSECURE` to an unrecognized value would make this
        // test print a spurious warning, unlike every other test in this
        // module which is already hermetic against that.
        temp_env::with_vars(
            [
                ("KLAAY_API_URL", Some("https://from-env.example.com")),
                ("KLAAY_ALLOW_INSECURE", None),
                ("KLAAY_WEB_URL", None),
            ],
            || {
                let result = Config::resolve(None, None, false);
                assert_eq!(
                    result
                        .expect("a safe https URL from the env var should resolve")
                        .api_url(),
                    "https://from-env.example.com"
                );
            },
        );
    }

    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_reads_klaay_allow_insecure_env_var_as_an_opt_in() {
        // `KLAAY_API_URL` wrapped alongside `KLAAY_ALLOW_INSECURE` for the
        // same reason `resolve_falls_back_to_klaay_api_url_env_var_when_
        // flag_is_none` does - `api_url_flag` being `Some(...)` here means
        // `.or_else`'s laziness never actually reads `KLAAY_API_URL`, so
        // this specific test doesn't strictly need the isolation today, but
        // matching the sibling test's pattern means a future test author
        // copying this one as a template for a `None`-flag case inherits the
        // isolation automatically instead of silently missing it.
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", Some("true")),
                ("KLAAY_API_URL", None),
                ("KLAAY_WEB_URL", None),
            ],
            || {
                // No `--force-insecure` flag (`false`) - only the env var opts in.
                let result = Config::resolve(Some("http://example.com".to_string()), None, false);
                assert!(result.is_ok());
            },
        );
    }

    /// Directly exercises the concern this test module didn't cover before:
    /// a typo in the `"1" | "true" | "yes"` match arm (e.g. accidentally
    /// including a value this CLI doesn't actually accept, like `"on"`)
    /// would silently widen what counts as an opt-in. This asserts the
    /// negative - an unrecognized value must NOT be treated as truthy.
    #[test]
    #[serial_test::serial(config_env_vars)]
    fn resolve_does_not_treat_an_unrecognized_klaay_allow_insecure_value_as_truthy() {
        temp_env::with_vars(
            [
                ("KLAAY_ALLOW_INSECURE", Some("on")),
                ("KLAAY_API_URL", None),
                ("KLAAY_WEB_URL", None),
            ],
            || {
                let result = Config::resolve(Some("http://example.com".to_string()), None, false);
                assert!(result.is_err());
            },
        );
    }
}
