// SPDX-License-Identifier: GPL-3.0-or-later
use crate::config;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

// `Zeroize`/`ZeroizeOnDrop` on the whole struct (not just relying on the
// `token` field's own `Zeroizing` wrapper) - every field type here already
// implements `Zeroize` (String and Option<String> both do, directly in the
// zeroize crate), so this covers every *clone* of a `StoredToken` too - e.g.
// the ones held in token_store.rs's file-fallback map, which would
// otherwise leave a residual token copy in memory when that map's own drop
// runs, unprotected by the original's `Zeroizing` wrapper.
//
// Deliberately does NOT derive `Debug` - unlike `Serialize` (needed for its
// one real job, writing/reading the credentials file/keyring entry, where
// the plaintext token has to round-trip), a `Debug` impl has no legitimate
// use here and would only ever exist for ad-hoc `eprintln!("{:?}", ...)`
// debugging that would print the bearer token in full. If a future change
// needs `Debug` for some other reason, hand-write it to redact `token`
// (matching `sso.rs`'s `IdTokenFields`) rather than deriving it.
#[derive(Serialize, Deserialize, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct StoredToken {
    // A long-lived (3-month) bearer credential - zeroized on drop for
    // consistency with how the password/id_token are handled during login
    // (see auth.rs, sso.rs). `Deserialize`/`Serialize` still work via
    // zeroize's "serde" feature, already enabled in Cargo.toml.
    pub(crate) token: zeroize::Zeroizing<String>,
    pub(crate) api_url: String,
    pub(crate) account_id: Option<String>,
    pub(crate) email: Option<String>,
}

/// The file-fallback format: every environment's token keyed by its own
/// api_url, not just the single most-recently-saved one - otherwise logging
/// into a second environment (e.g. local dev after production) on a machine
/// with no OS keychain would silently overwrite the first one's token, and
/// `load()` would report "not logged in" for it with no explanation.
///
/// `BTreeMap`, not `HashMap` - a `HashMap`'s iteration order is randomized
/// per process, so every rewrite of this file would serialize its entries in
/// a different byte order even when the logical contents are identical,
/// bumping the file's mtime and producing spurious diffs for any tool
/// watching it (backup software, dotfile version control). `BTreeMap`'s
/// deterministic key order costs nothing meaningful for a map that
/// realistically holds a handful of entries.
type FileFallbackMap = BTreeMap<String, StoredToken>;

// Only ever read here, not a `config.rs` concern - moved out of that module
// since nothing outside this file references it, and keeping keyring-specific
// detail alongside the code that actually calls `Entry::new` makes it easier
// to find/change than having it live in a general-purpose config module.
//
// `"klaay"` - the installed binary name (`[[bin]] name = "klaay"` in
// Cargo.toml), not the Cargo package name (`klaay-cli`). OS keychain UIs
// (Keychain Access, Credential Manager, `secret-tool`) display this service
// name, so a user searching for "klaay" needs to actually find an entry
// under that name - and it's a stable, independent value rather than one
// derived from the package name, so renaming the Cargo package later
// doesn't silently change it and orphan every previously stored token.
const KEYRING_SERVICE: &str = "klaay";

fn keyring_entry(api_url: &str) -> Result<Entry, keyring::Error> {
    // Scope the keyring account name by api_url so switching environments
    // (e.g. production vs a local dev server) doesn't clobber each other's token.
    Entry::new(KEYRING_SERVICE, api_url)
}

/// Stores the token, in the OS keychain when available or a fallback file
/// otherwise. Returns an error string on failure rather than panicking -
/// this runs after `auth::login_with_credentials` has already printed a
/// "Logged in as ..." message, so a hard failure here needs to surface
/// clearly rather than crash the process.
pub(crate) fn save(stored: &StoredToken) -> Result<(), SaveTokenError> {
    // `keyring_entry` is always called here (there's no branch that skips
    // it), so "the keychain was attempted" is unconditionally true by the
    // time this function reaches the fallback path below - unlike the
    // earlier version, which only considered it "attempted" when
    // `Entry::new` itself returned `Ok`. `Entry::new` can fail for reasons
    // that have nothing to do with "no backend available" (e.g. an
    // OS-level API error, invalid characters in the service name), and
    // that case still deserves its own warning here rather than silently
    // falling through to a generic "no backend" message downstream that
    // doesn't match what actually happened.
    let keyring_entry_result = keyring_entry(&stored.api_url);
    if let Err(e) = &keyring_entry_result {
        eprintln!("Warning: could not construct a keyring entry ({e}); falling back to file.");
    }
    if let Ok(entry) = keyring_entry_result {
        // The serialized JSON contains the cleartext bearer token, same as
        // `stored.token` itself - wrapping it in `Zeroizing` before it's
        // handed to `set_password` keeps that plaintext copy from lingering
        // in memory any longer than `stored.token`'s own Zeroizing wrapper
        // already ensures for the un-serialized value.
        let serialized: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            serde_json::to_string(stored)
                .map_err(|e| SaveTokenError::Other(format!("could not serialize token: {e}")))?,
        );
        match entry.set_password(&serialized) {
            Ok(()) => {
                // Cleans up a file-fallback entry for this same api_url left
                // over from an earlier login where the keychain was
                // unavailable - otherwise it would keep sitting there and
                // `load()` could end up serving it (stale relative to the
                // one just written to the keychain) the next time the
                // keychain has a transient read failure. Best-effort: this
                // is tidying up, not the write that just succeeded.
                remove_stale_file_entry(&stored.api_url);
                return Ok(());
            }
            Err(e) => eprintln!(
                "Warning: could not store token in OS keychain ({e}); falling back to file."
            ),
        }
    }

    let path = save_to_file(stored)?;
    // A single, always-accurate reason rather than branching on whether
    // `Entry::new` itself succeeded - that would only tell us whether entry
    // *construction* worked, not whether a real keychain backend exists
    // (that's only actually exercised by `set_password`, which may be the
    // step that failed instead). The specific failure - entry construction
    // or the write itself - was already reported above via its own warning.
    eprintln!(
        "Note: the OS keychain wasn't usable, storing the token in {} instead (permissions restricted to your user).",
        path.display()
    );
    Ok(())
}

/// Distinguishes *why* `load_file_map` failed, not just that it did - `Io`
/// (permission error, disk error, anything read-related short of the file
/// simply not existing) is a transient environmental problem that a retry
/// might resolve; `Parse` means the file's contents themselves are
/// corrupt/incompatible and no retry will fix that (`save_to_file`
/// propagates both the same way, rather than auto-recovering from `Parse` by
/// overwriting the file - see that function's own comment for why); `Config`
/// means the environment itself is misconfigured (e.g. no HOME/USERPROFILE
/// to resolve a config directory under) - not an I/O failure at all, so
/// labeling it "I/O error" (as an earlier version of this type's `Display`
/// impl did by folding it into `Io`) misleads a reader into thinking a retry
/// or a filesystem fix might help, when what's actually needed is fixing the
/// shell environment.
enum LoadFileMapError {
    Io(String),
    Parse(String),
    Config(String),
}

impl std::fmt::Display for LoadFileMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Prefixed with which variant this is - the two produced identical
        // output before, so a call site's `eprintln!("Warning: {e}")` gave a
        // reader no way to tell a transient I/O failure ("disk error, retry
        // might work") from a corrupt file ("parse error, manual
        // intervention needed"), even though `save_to_file`'s own recovery
        // behavior already treats the two differently (see the type's own
        // doc comment above).
        match self {
            LoadFileMapError::Io(message) => write!(f, "I/O error: {message}"),
            LoadFileMapError::Parse(message) => write!(f, "parse error: {message}"),
            LoadFileMapError::Config(message) => write!(f, "configuration error: {message}"),
        }
    }
}

/// `save`/`save_to_file`'s own error type - collapses every failure they can
/// produce (a `LoadFileMapError` of any variant, directory-creation,
/// serialization, or atomic-write errors) down to just the one distinction
/// their caller can actually act on differently: `CorruptedFile` (a
/// `LoadFileMapError::Parse`) means the credentials file itself is intact on
/// disk but unreadable - human-fixable, and specifically *not* auto-repaired
/// by overwriting it (see `save_to_file`'s own comment) - so a caller can
/// point the user at the file to fix or delete by hand. `Other` covers every
/// other cause (transient I/O, a misconfigured environment, a `keyring`
/// failure, a bug), where there's nothing more specific to say than the
/// message itself.
pub(crate) enum SaveTokenError {
    CorruptedFile(String),
    Other(String),
}

impl std::fmt::Display for SaveTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Prefixed per variant, matching `LoadFileMapError`'s own `Display`
        // impl above - without this, both variants formatted identically,
        // so any future caller that formats a `SaveTokenError` directly
        // (`eprintln!("{e}")`, logging) rather than pattern-matching it
        // (as `auth.rs`'s current caller does) would silently lose the
        // distinction this type exists to preserve.
        match self {
            SaveTokenError::CorruptedFile(message) => {
                write!(f, "corrupted credentials file: {message}")
            }
            SaveTokenError::Other(message) => write!(f, "{message}"),
        }
    }
}

/// Loads the file-fallback map. `Ok` distinguishes "file doesn't exist yet"
/// (expected, e.g. first run - returns an empty map) from "file exists but
/// couldn't be parsed" (a corrupted or incompatible-version credentials
/// file), which is now an `Err` rather than silently treated as "no
/// credentials" - a caller about to *write* the file needs to know about a
/// parse failure so it doesn't blindly overwrite (and thereby permanently
/// destroy) every other environment's still-good stored token.
fn load_file_map() -> Result<FileFallbackMap, LoadFileMapError> {
    // An `Err`, not `Ok(FileFallbackMap::default())` - `credentials_
    // fallback_path()` only returns `None` when the config directory itself
    // can't be resolved (e.g. HOME/USERPROFILE unset), a transient
    // environment problem distinct from "never logged in". Silently
    // treating it as an empty map would make `load()` report "not logged
    // in" even when the user has a valid stored session, with no error to
    // explain why - `save_to_file` already treats a missing path as an
    // `Err` for the same reason.
    let Some(path) = config::credentials_fallback_path() else {
        return Err(LoadFileMapError::Config(
            "could not determine the credentials file path (is HOME/USERPROFILE set?)".to_string(),
        ));
    };
    // Zeroized on drop - this buffer holds every stored environment's
    // cleartext bearer token for as long as it's alive, same as the
    // serialized copies produced when writing the file.
    let contents: zeroize::Zeroizing<String> =
        zeroize::Zeroizing::new(match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FileFallbackMap::default())
            }
            Err(e) => {
                return Err(LoadFileMapError::Io(format!(
                    "could not read credentials file {}: {e}",
                    path.display()
                )));
            }
        });
    serde_json::from_str(&contents).map_err(|e| {
        LoadFileMapError::Parse(format!(
            "credentials file {} could not be parsed ({e}) - remove or fix it manually, then run `{} login` again",
            path.display(),
            crate::config::bin_name()
        ))
    })
}

/// Best-effort removal of `api_url`'s entry from the file fallback, called
/// from `save()` right after a successful keychain write - not part of any
/// function's success/failure contract, so every failure path here is
/// silently swallowed rather than surfaced. This exists purely to stop a
/// stale file-fallback entry (left over from a login where the keychain
/// wasn't available) from ever being served by `load()` in place of the
/// fresher token that was just written to the keychain.
fn remove_stale_file_entry(api_url: &str) {
    let Ok(mut map) = load_file_map() else {
        return;
    };
    if map.remove(api_url).is_none() {
        return;
    }
    let Some(path) = config::credentials_fallback_path() else {
        return;
    };
    if map.is_empty() {
        // Warned on failure, matching the multi-entry rewrite path just
        // below - a failed removal here leaves the exact same stale entry on
        // disk (now the file's only entry, since `map.remove` above already
        // ran) that the multi-entry path is warning about; there's no reason
        // for this path to stay silent about the identical risk. `NotFound`
        // is not warned about - it means a concurrent process already
        // deleted the file between `load_file_map()`'s read and this call,
        // so the cleanup goal (the file no longer has this stale entry) is
        // already achieved, same as `delete()`'s equivalent path treats it.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "Warning: could not remove stale file-fallback entry for {api_url} after keychain write ({e}); it may be served on a future keychain failure."
            ),
        }
        return;
    }
    // Warned on failure, unlike the other silent paths above (which return
    // early because there was nothing to persist in the first place) - this
    // function already removed the entry from `map` in memory, so either a
    // failed serialization or a failed write here leaves the stale entry
    // sitting in the file on disk, where a future keychain read failure
    // could serve it in place of the fresher token this function was trying
    // to make authoritative. Worth a warning given these files hold
    // cleartext bearer tokens. Matched explicitly (not `if let Ok(json) =
    // ... { ... }`) so a `serde_json::to_string` failure - not just the
    // already-warned `atomic_write_secure` failure - also surfaces a
    // warning instead of silently falling through.
    match serde_json::to_string(&map).map(zeroize::Zeroizing::new) {
        Ok(json) => {
            if let Err(e) = atomic_write_secure(&path, &json) {
                eprintln!(
                    "Warning: could not remove stale file-fallback entry for {api_url} after keychain write ({e}); it may be served on a future keychain failure."
                );
            }
        }
        Err(e) => {
            eprintln!(
                "Warning: could not serialize file-fallback credentials while removing the stale entry for {api_url} after keychain write ({e}); it may be served on a future keychain failure."
            );
        }
    }
}

/// Writes `data` to `path` atomically (via a sibling temp file + rename),
/// creating it with 0600 permissions on Unix from the start - shared by
/// `save_to_file` and `delete`'s rewrite-without-one-entry path, so neither
/// can accidentally create the temp file with the platform-default (often
/// world-readable) permissions before renaming it over the real credentials
/// file.
/// Takes `&Zeroizing<String>`, not a plain `&str` - every real call site
/// already only ever has a `Zeroizing<String>` on hand (this always writes
/// credential data), so the plain `&str` signature gave the type system no
/// way to catch a future caller accidentally passing an unprotected `String`
/// or string literal. `data.as_bytes()` below still works via `Deref`, so
/// the body needs no change.
///
/// Unix-only implementation - see the `#[cfg(not(unix))]` twin below for why
/// this platform split exists as two separate function bodies rather than a
/// single one with an internal `#[cfg]` branch: the rest of this body (the
/// write/sync/rename sequence) only makes sense once a real, permission-
/// restricted file handle exists, so there's no shared code to keep in one
/// function once that first step diverges by platform.
#[cfg(unix)]
fn atomic_write_secure(path: &Path, data: &zeroize::Zeroizing<String>) -> Result<(), String> {
    // Includes the process id (so two concurrent CLI invocations - e.g. a
    // `klaay login` racing a `klaay logout` for a different environment, or
    // two logins in parallel scripts - don't race on the same temp file
    // name) mixed with a nanosecond timestamp (since pids get recycled by
    // the OS - two successive invocations reusing the same pid, common in
    // rapid-fire CI/container environments, would otherwise still collide).
    // Same technique schema.rs's cache-file writer already uses, for
    // consistency.
    // The atomic counter is mixed in unconditionally, not just as a
    // clock-before-epoch fallback - `SystemTime`'s actual resolution is
    // platform-dependent (some platforms/clock sources only guarantee
    // microsecond or millisecond precision despite `Duration`'s
    // nanosecond-capable type), so two calls within the same process during
    // the same coarse tick could otherwise still produce the same "unique"
    // value. The counter alone already guarantees uniqueness per call in
    // this process; the timestamp is kept alongside it for readability when
    // inspecting a leftover temp file, not as the uniqueness guarantee
    // itself.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Explicitly `u128` (`Duration::as_nanos`'s real return type) - left
    // uninferred, a future edit could accidentally introduce a truncating
    // `as u64` cast here that would silently break uniqueness for
    // current-era timestamps (already past `u64::MAX` nanoseconds since the
    // epoch) without any compiler error to catch it.
    let nanos: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let unique = format!("{nanos}-{counter}");
    let tmp_name = format!(
        "{}.{}-{unique}.tmp",
        path.file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("credentials"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);

    // `create_new` (not `create(true).truncate(true)`, which would silently
    // overwrite an existing file at this exact path) - matches schema.rs's
    // atomic cache writer. If the pid+nanos+counter uniqueness scheme above
    // ever produced a genuine collision (a coarser-than-nanosecond clock
    // plus a wrapped counter, or a stale orphan temp file from a previous
    // crash happening to share this exact name), this fails loudly with
    // `AlreadyExists` instead of quietly tearing another write in progress.
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| {
                format!(
                    "could not create temp credentials file {}: {e}",
                    tmp_path.display()
                )
            })?
    };

    if let Err(e) = file.write_all(data.as_bytes()) {
        drop(file); // close before remove_file below
                    // Same reasoning as the rename-failure path below - this temp file
                    // still holds the cleartext token(s) being written, so a cleanup
                    // failure here (not just the write failure itself) deserves its own
                    // warning rather than a silent `let _ =`, which would otherwise
                    // leave a credential-bearing file on disk with no indication it
                    // exists.
        if let Err(rm_err) = fs::remove_file(&tmp_path) {
            eprintln!(
                "Warning: could not clean up temp credentials file {} (write failed: {e}; removal of temp file also failed: {rm_err})",
                tmp_path.display()
            );
        }
        return Err(format!(
            "could not write temp credentials file {}: {e}",
            tmp_path.display()
        ));
    }
    // Ensure the data is actually durable before the rename makes it live -
    // otherwise a power failure between the rename and the OS flushing its
    // page cache could leave a zero-length credentials file.
    if let Err(e) = file.sync_all() {
        drop(file); // close before remove_file below
                    // Same reasoning as above - a `sync_all` failure can leave a
                    // fully-written (not partial) credential-bearing temp file, so a
                    // subsequent cleanup failure is just as worth surfacing.
        if let Err(rm_err) = fs::remove_file(&tmp_path) {
            eprintln!(
                "Warning: could not clean up temp credentials file {} (sync failed: {e}; removal of temp file also failed: {rm_err})",
                tmp_path.display()
            );
        }
        return Err(format!(
            "could not flush temp credentials file {}: {e}",
            tmp_path.display()
        ));
    }
    drop(file); // close before the rename below, for the same reason

    fs::rename(&tmp_path, path).map_err(|e| {
        // If this cleanup itself fails, the temp file - which still holds
        // the cleartext token(s) that were being written - is left behind
        // on disk with no notification. The caller's returned error only
        // mentions the rename failure, so surface the leak separately here
        // rather than silently discarding it via `let _ =`.
        if let Err(rm_err) = fs::remove_file(&tmp_path) {
            // Cause and effect spelled out explicitly, rather than folding
            // the rename error into a parenthetical after "after a failed
            // rename" - that phrasing read as if the *removal* was what
            // failed after the rename, when both `e` (the rename failure)
            // and `rm_err` (the subsequent cleanup failure) are being
            // reported together.
            eprintln!(
                "Warning: could not clean up temp credentials file {} (rename failed: {e}; removal of temp file also failed: {rm_err})",
                tmp_path.display()
            );
        }
        format!("could not replace credentials file {}: {e}", path.display())
    })
}

/// Non-Unix twin of the function above: refuses to write the fallback
/// credentials file at all, rather than writing it with the platform-default
/// (often world-readable) permissions.
///
/// Correctly restricting a Windows file's ACL needs a Windows-specific ACL
/// crate (e.g. `windows-acl`) to remove inherited ACEs, resolve the current
/// user's SID, and apply a new security descriptor atomically with file
/// creation - a real, distinct feature, and one this project has no Windows
/// machine to verify against (a subtly wrong ACL is worse than an honest
/// refusal: it would look fixed while still leaving the file exposed).
///
/// This file only ever holds this fallback role because `save()`'s primary
/// path - the OS keychain (Windows Credential Manager) - already failed;
/// Credential Manager itself has no equivalent gap. So refusing to write the
/// fallback file at all here doesn't block ordinary Windows use, and only
/// ever fires in the already-rare case where Credential Manager itself is
/// unavailable - in which case a hard error is strictly safer than silently
/// persisting a 3-month bearer token to a world-readable file. `save()`'s
/// caller already handles this `Err` by telling the user they'll need to log
/// in again next time - not a crash.
#[cfg(not(unix))]
fn atomic_write_secure(path: &Path, _data: &zeroize::Zeroizing<String>) -> Result<(), String> {
    Err(format!(
        "the OS credential store is unavailable, and this platform has no ACL-restricted fallback file storage implemented yet, so the token can't be stored safely at {}",
        path.display()
    ))
}

/// Merges `stored` into the file-fallback map (keyed by api_url), writes it
/// out via `atomic_write_secure`, and returns the path written to - callers
/// (just `save`) use the returned path directly instead of doing a second,
/// separately-fallible lookup of the same path after this already succeeded.
///
/// Accepted limitation: this is a read (`load_file_map`) - modify (insert) -
/// write (`atomic_write_secure`) cycle with no file lock around it, so two
/// concurrent CLI invocations that both hit the file fallback (e.g. `klaay
/// login` for two different `api_url`s running in parallel scripts) can lose
/// an update - whichever finishes its write second wins, silently dropping
/// the other's entry. `atomic_write_secure` still guarantees each individual
/// write is atomic (no torn/partial file), just not that concurrent
/// read-modify-write cycles serialize against each other. Not fixed here:
/// adding real locking means a new dependency (e.g. `fd-lock`/`fs2`) for a
/// narrow race that only matters when the OS keychain backend is
/// unavailable *and* multiple CLI invocations run at the same instant - a
/// real gap, but a distinct addition rather than a small fix.
fn save_to_file(stored: &StoredToken) -> Result<std::path::PathBuf, SaveTokenError> {
    let dir = config::config_dir().ok_or_else(|| {
        SaveTokenError::Other(
            "could not determine your home directory (no HOME/USERPROFILE set)".to_string(),
        )
    })?;
    // 0700 (owner-only) rather than create_dir_all's platform-default (often
    // 0755, world-readable+executable) - otherwise any other local user could
    // enumerate this directory and learn the credentials filename even
    // though the file itself is 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| {
                SaveTokenError::Other(format!(
                    "could not create config directory {}: {e}",
                    dir.display()
                ))
            })?;
        // `DirBuilder`'s `mode` only applies to directories this call
        // actually creates - confirmed directly in the standard library's
        // `create_dir_all` implementation, an already-existing directory
        // takes the early `Err(_) if path.is_dir() => return Ok(())` path
        // and never has its mode touched at all. Set unconditionally here so
        // a directory left over from before this permissions check existed
        // (or created some other way, with a looser umask) still ends up
        // 0700 on every `klaay login`, not just its first-ever creation.
        //
        // Warned on failure, not propagated via `?` - on every login after
        // the first, this directory already exists and (in the overwhelming
        // common case) is already 0700, making this call pure defensive
        // redundancy rather than something this login actually depends on.
        // Turning a transient failure here (a momentary permissions race, a
        // read-only remount) into a hard error would discard a freshly
        // authenticated token that already succeeded - the credentials file
        // written just below is still created with its own 0600 permissions
        // regardless of what happens to the parent directory's, so the
        // file's own contents stay confidential either way.
        if let Err(e) = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)) {
            eprintln!(
                "Warning: could not set permissions on config directory {}: {e}",
                dir.display()
            );
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(&dir).map_err(|e| {
        SaveTokenError::Other(format!(
            "could not create config directory {}: {e}",
            dir.display()
        ))
    })?;

    // A `Parse` failure now propagates via `?` the same as an `Io` failure -
    // an earlier version of this function instead auto-recovered by
    // overwriting the file with a fresh map containing just this login,
    // reasoning that a corrupted file's other entries can't be recovered
    // either way so there was nothing lost by discarding them immediately.
    // But that overwrite is irreversible the moment it happens: if the
    // corruption were something a human could fix by hand (a stray
    // character, a truncated write), auto-overwriting destroys that
    // possibility permanently and silently - the warning is easy to miss
    // in scrollback, and even a user who does see it and hits Ctrl-C loses
    // every other stored environment's token the instant the write
    // completes, with no confirmation prompt. Propagating instead means
    // *this* login's token fails to persist to the file fallback (the
    // caller already has a "logged in, but the token could not be stored"
    // path for exactly this outcome), but leaves the corrupted file
    // otherwise untouched for the user to inspect or repair by hand, per
    // `load_file_map`'s own parse-error message.
    //
    // `Parse` maps to `SaveTokenError::CorruptedFile` specifically (not
    // folded into `Other` like every other variant/error source in this
    // function) - it's the one case here a caller can react to differently:
    // the file is intact but needs a human, not a retry.
    let mut map = load_file_map().map_err(|e| match e {
        LoadFileMapError::Parse(message) => SaveTokenError::CorruptedFile(message),
        LoadFileMapError::Io(_) | LoadFileMapError::Config(_) => {
            SaveTokenError::Other(e.to_string())
        }
    })?;
    // `api_url` unavoidably goes through two `.clone()` calls on this one
    // line - `stored.api_url.clone()` for the map key, and the `api_url`
    // field inside `stored.clone()` for the map value - since a
    // `BTreeMap<String, StoredToken>`'s key and the value's own field are
    // genuinely separate allocations. That's 2 clone *operations*, and (with
    // `stored.api_url` itself, never dropped by this line) 3 copies of the
    // string *alive* afterward - two different counts, not one restated
    // twice. A prior version of this comment claimed cloning `stored` first
    // and reading the key back out of that same clone avoided the
    // duplication - it didn't; the clone count was identical either way,
    // just spread across two lines instead of stated plainly here.
    map.insert(stored.api_url.clone(), stored.clone());
    // Zeroized on drop, same as `load_file_map`'s read buffer - this string
    // holds every stored environment's cleartext bearer token in one place.
    let json: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
        serde_json::to_string(&map)
            .map_err(|e| SaveTokenError::Other(format!("could not serialize credentials: {e}")))?,
    );

    // Reuses config::credentials_fallback_path() (single source of truth for
    // the filename) rather than re-deriving it here. `dir` above already
    // proved the home directory resolves, so this is not expected to fail in
    // practice - but propagating via `?` rather than `.expect()` means a
    // future refactor of either function that breaks that assumption
    // degrades to a clean error instead of an unrecoverable panic.
    let path = config::credentials_fallback_path().ok_or_else(|| {
        SaveTokenError::Other("could not determine credentials file path".to_string())
    })?;
    #[cfg(unix)]
    remove_stale_credential_temp_files(&dir, &path);
    atomic_write_secure(&path, &json).map_err(SaveTokenError::Other)?;
    Ok(path)
}

/// Best-effort cleanup of leftover `credentials.json.<pid>-<unique>.tmp`
/// files from a process that was killed (SIGKILL, power loss, OOM) between
/// `atomic_write_secure` creating its temp file and renaming it over the
/// real credentials path - mirrors `schema.rs`'s
/// `remove_stale_cache_temp_files`, but this is the more sensitive case:
/// those temp files hold cleartext bearer tokens for every stored
/// environment, not just a cached, re-fetchable OpenAPI spec. Only removes
/// files older than an hour, so a temp file actively being written by
/// another concurrent CLI invocation right now is never touched.
///
/// `#[cfg(unix)]` - both call sites are themselves `#[cfg(unix)]`-gated,
/// since these temp files are only ever created by `atomic_write_secure`'s
/// `#[cfg(unix)]` branch (its `#[cfg(not(unix))]` twin never writes a file at
/// all). Without this gate, every `save`/`delete` on a non-Unix platform paid
/// for an `fs::read_dir` scan that could never find anything.
#[cfg(unix)]
fn remove_stale_credential_temp_files(dir: &Path, credentials_path: &Path) {
    const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);
    let Some(base_name) = credentials_path.file_name().and_then(|f| f.to_str()) else {
        return;
    };
    let prefix = format!("{base_name}.");
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        // Requires the portion between `prefix` and `.tmp` to look like this
        // crate's own "<pid>-<nanos>-<counter>" naming (digits and hyphens
        // only, matching `atomic_write_secure`'s `tmp_name` format exactly) -
        // `starts_with(prefix)`/`ends_with(".tmp")` alone would also match
        // e.g. `credentials.json.editor-backup.tmp`, a plausible name for an
        // editor or another tool to drop in this same config directory, and
        // silently delete it an hour later even though this CLI never wrote
        // it.
        // `checked_sub`-guarded, not a bare `name.len() - ".tmp".len()` slice
        // - a file named exactly `{base_name}.tmp` (e.g. `credentials.json.
        // tmp`) satisfies both `starts_with(&prefix)` and `ends_with(".tmp")`
        // above (the prefix's own trailing dot immediately precedes "tmp"),
        // but `name.len() - 4` then lands *before* `prefix.len()`, making the
        // slice below a reversed range that panics at runtime. Editors and
        // other tools routinely create `filename.tmp` sidecar files, and
        // this scan runs on every login/logout, so that panic would crash
        // the CLI process for any user with such a file present.
        let Some(middle_end) = name.len().checked_sub(".tmp".len()) else {
            continue;
        };
        let Some(middle) = name.get(prefix.len()..middle_end) else {
            continue;
        };
        // `.all()` on an empty iterator is vacuously `true`, so without the
        // explicit `is_empty()` check a file named exactly
        // `credentials.json..tmp` (double dot, empty middle) would pass this
        // filter - `atomic_write_secure` never generates that name, but
        // another tool dropping a file with that pattern in this same
        // directory shouldn't be silently deleted either.
        // Exactly 2 hyphens, not just "digits and hyphens only" - the real
        // format is `{pid}-{nanos}-{counter}`, which always has exactly 2.
        // Without this, a bare number like `credentials.json.12345.tmp`
        // (zero hyphens) passes the character-set check above even though
        // this CLI never generates that shape, and would still be deleted an
        // hour later. Tightened to `!= 2` (not `< 2`) to actually match this
        // stated invariant - a name with 3+ hyphens is just as much outside
        // the generated shape as one with fewer than 2.
        if middle.is_empty()
            || !middle.chars().all(|c| c.is_ascii_digit() || c == '-')
            || middle.chars().filter(|&c| c == '-').count() != 2
        {
            continue;
        }
        // Symmetric threshold in both directions - matches
        // `schema::remove_stale_cache_temp_files`'s handling of the same
        // future-timestamp case (clock skew, an NTP correction, a file
        // copied from another host), except here the stakes are higher:
        // these temp files hold cleartext bearer tokens for every stored
        // environment. A `duration_since` failure (the timestamp is in the
        // future) is checked against the same `STALE_AFTER` bound via
        // `SystemTimeError::duration()` rather than treated as
        // unconditionally not-stale (which would leave a credential-bearing
        // file un-cleaned indefinitely) or unconditionally stale (which
        // could delete a file a concurrent process is still actively
        // writing to, if its clock is only trivially ahead).
        // `symlink_metadata` (not `entry.metadata()`) for the staleness
        // check, and its own `is_file()` for the type guard below - the same
        // fix applied to `schema::remove_stale_cache_temp_files`'s
        // equivalent scan. `entry.metadata()` follows a symlink to its
        // target's mtime, so a symlink named like a stale temp file would
        // see `is_stale = true` from a stale target while never being
        // caught by a `file_type()`-based type guard (which doesn't follow
        // it) - using one non-following metadata read for both checks keeps
        // them describing the same entry.
        //
        // The type guard itself was missing entirely before this fix -
        // unlike `schema.rs`'s equivalent cache-temp-file scan, this loop
        // passed `entry.path()` straight to `fs::remove_file` once `is_stale`
        // was true, with no check that the entry was even a regular file.
        // Given this scan handles credential-bearing temp files (a higher
        // sensitivity than the cache case), it warranted at least the same
        // guard, not less.
        let symlink_meta = entry.path().symlink_metadata().ok();
        let is_stale = match symlink_meta.as_ref().and_then(|m| m.modified().ok()) {
            Some(modified) => match std::time::SystemTime::now().duration_since(modified) {
                Ok(age) => age > STALE_AFTER,
                Err(e) => e.duration() > STALE_AFTER,
            },
            None => false,
        };
        let is_regular_file = symlink_meta.as_ref().map(|m| m.is_file()).unwrap_or(false);
        if is_stale && is_regular_file {
            // Warned on failure, not silently swallowed - unlike
            // `schema.rs`'s equivalent cache-temp-file scan, these files
            // hold cleartext bearer tokens for every stored environment (per
            // this function's own doc comment), so a removal failure
            // leaving one behind deserves the same visibility every other
            // credential-file cleanup failure in this module already gets.
            if let Err(e) = fs::remove_file(entry.path()) {
                eprintln!(
                    "Warning: could not remove stale credential temp file {} ({e}); it holds cleartext tokens and should be deleted manually.",
                    entry.path().display()
                );
            }
        }
    }
}

pub(crate) fn load(api_url: &str) -> Option<StoredToken> {
    // Mirrors `save()`/`delete()`: an `Err` here means `keyring_entry` itself
    // couldn't be constructed (e.g. an OS-level error, or a character in
    // `api_url` the keyring backend rejects) - not the "no entry stored"
    // case handled below. Warning here (rather than silently falling
    // straight to the file fallback) surfaces a persistent keychain
    // misconfiguration instead of masking it as a stale/missing credential.
    let keyring_entry_result = keyring_entry(api_url);
    if let Err(e) = &keyring_entry_result {
        eprintln!("Warning: could not construct a keyring entry for {api_url} ({e}); falling back to file.");
    }
    if let Ok(entry) = keyring_entry_result {
        match entry.get_password() {
            Ok(json) => {
                // Zeroized on drop - holds the cleartext bearer token, same
                // as `load_file_map`'s read buffer and `save()`'s serialized
                // copy. Bound as its own `let`, matching the pattern used
                // there, rather than wrapped inline as a call argument.
                let json: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(json);
                // KNOWN GAP, accepted rather than silently assumed away
                // (same posture as auth.rs's `process::exit`/`Zeroizing`
                // interaction): `serde_json::from_str` allocates its own
                // plain (non-`Zeroizing`) `String` for every JSON string
                // field it parses - `token`, `api_url`, `email` - as part of
                // building the returned `StoredToken`. Wrapping the *input*
                // `json` buffer in `Zeroizing` (above) protects that one
                // buffer, and `StoredToken`'s own `Zeroize`/`ZeroizeOnDrop`
                // protects the final struct's fields once constructed - but
                // serde_json provides no hook to deserialize a JSON string
                // directly into a `Zeroizing<String>` without an intermediate
                // plain allocation, so the freed backing buffer of that
                // intermediate `token` `String` is never zeroized. A real fix
                // needs a custom `Deserialize` impl that borrows/copies
                // straight into a pre-zeroized buffer - not attempted here.
                // The same gap applies to `load_file_map`'s equivalent
                // `serde_json::from_str` call below.
                match serde_json::from_str::<StoredToken>(&json) {
                    Ok(stored) => return Some(stored),
                    // Doesn't fall through to the file fallback below - a
                    // parsed keyring entry for this exact api_url means the
                    // keychain is the authoritative store for it, so the
                    // file map (which may hold a stale or unrelated entry
                    // left over from before the keychain became available)
                    // must not be consulted instead.
                    Err(e) => {
                        // Names a recovery path, matching the equivalent
                        // file-fallback error message below - without it, a
                        // corrupted keyring entry leaves the user stuck
                        // hitting this same warning on every command with no
                        // indication of how to clear it (most users don't
                        // know how to open the OS keychain UI directly).
                        // `logout` deletes this entry outright regardless of
                        // whether it parses, so it's the right recovery step.
                        eprintln!(
                            "Warning: keyring entry for {api_url} could not be parsed ({e}) - treating as not logged in. Run `{} logout` then `{} login` again to recover.",
                            crate::config::bin_name(),
                            crate::config::bin_name()
                        );
                        return None;
                    }
                }
            }
            // NoEntry alone means "no token stored here" - the expected,
            // already-designed-for case that `save()` silently falls back to
            // a file for, so no warning needed. Every other error - whether
            // a known-transient one (NoStorageAccess/PlatformFailure: the
            // keychain exists but is temporarily unreachable - locked
            // screen, no Secret Service daemon right now) or an unrecognized
            // category - falls through to the file fallback the same way.
            // `save()` already falls back to file on *any* keyring write
            // error, not just those two known variants; treating an
            // unrecognized error as an automatic `return None` here would be
            // asymmetric with that and make the file fallback permanently
            // unreadable for a user whose keychain consistently errors with
            // something else - exactly the case the fallback exists to cover.
            Err(keyring::Error::NoEntry) => {}
            Err(e) => {
                eprintln!(
                    "Warning: could not read keyring entry for {api_url} ({e}); falling back to file."
                );
            }
        }
    }

    match load_file_map() {
        Ok(mut map) => map.remove(api_url),
        Err(e) => {
            eprintln!("Warning: {e}");
            None
        }
    }
}

/// Turns "nothing found in the file fallback" into the right final result for
/// `delete()`, given what the keychain side already learned. A transient
/// keychain error plus no file-fallback entry is not the same thing as
/// genuinely never having logged in - `Ok(false)` would tell `auth::logout` to
/// print "Not logged in.", when the credential may in fact still be sitting
/// in a keychain that just couldn't be reached this time.
fn keychain_delete_result(
    removed_something: bool,
    keychain_delete_failed: bool,
) -> Result<bool, String> {
    if keychain_delete_failed && !removed_something {
        Err(
            "the keychain credential could not be removed due to a transient error \
             (see the warning above), and no file-fallback entry existed for this \
             API URL - it may still be present in the keychain; try logout again"
                .to_string(),
        )
    } else {
        Ok(removed_something)
    }
}

/// Removes the token for `api_url` from the keychain and/or the file
/// fallback. Returns an error string on failure so `auth::logout` can tell
/// the user their credentials might still be present, instead of always
/// printing "Logged out" regardless of whether the removal actually worked.
///
/// `Ok(bool)` - not just `Ok(())` - so the caller can tell "there was
/// something to remove and it's gone" from "there was nothing to remove in
/// either store" (both keyring `NoEntry` and no file-map entry), rather than
/// printing "Logged out (credentials removed)" even when nothing actually
/// was.
///
/// Same accepted no-file-locking limitation as `save_to_file`'s
/// read-modify-write cycle - a concurrent `save`/`delete` for a different
/// `api_url` racing against this one can lose an update.
pub(crate) fn delete(api_url: &str) -> Result<bool, String> {
    let mut removed_something = false;
    // Set only on a *transient* keychain error (NoStorageAccess,
    // PlatformFailure, etc.) - distinct from `removed_something` staying
    // `false`, which also covers the ordinary "there was genuinely nothing to
    // remove" case. Lets the two early returns below (reached when the file
    // fallback also has nothing for this api_url) tell those apart: if the
    // keychain lookup itself failed, "Ok(false)" would read as "not logged
    // in" when the credential may still be sitting in an unreachable
    // keychain - that has to surface as an error instead.
    let mut keychain_delete_failed = false;
    // Mirrors `save()`'s pattern: report a keyring entry *construction*
    // failure explicitly, rather than silently falling through the `if let
    // Ok` below as if the keychain had been cleanly checked and found
    // empty. Without this, an OS-level `Entry::new` error would leave the
    // user reading "Not logged in"/"Logged out" with no indication the
    // keychain was never actually consulted - it might still hold the
    // credential.
    let keyring_entry_result = keyring_entry(api_url);
    if let Err(e) = &keyring_entry_result {
        eprintln!(
            "Warning: could not construct a keyring entry ({e}); the keychain credential may not have been removed."
        );
    }
    if let Ok(entry) = keyring_entry_result {
        match entry.delete_credential() {
            Ok(()) => removed_something = true,
            Err(keyring::Error::NoEntry) => {}
            // Every other error (including NoStorageAccess/PlatformFailure,
            // which used to be silently ignored here) is warned about, not
            // silently swallowed as success - those two specifically mean
            // the keychain exists but is temporarily unreachable, not that
            // there was nothing to delete.
            //
            // Warned and proceeds to the file-fallback cleanup below, rather
            // than returning immediately - an earlier version returned here
            // on the reasoning that touching the file map while the
            // keychain deletion failed could leave an inconsistent state,
            // but that reasoning breaks down exactly when the credential
            // was never in the keychain to begin with: if `save()` fell
            // back to the file at login time (keychain unavailable then)
            // and the keychain is *still* unavailable now, this error fires
            // on every single `logout` call, permanently blocking the file
            // fallback from ever being reached and reported - the token
            // would live in that file forever with no way to remove it.
            // Proceeding here doesn't lose the keychain warning (still
            // printed above), and lets the file-fallback branch below
            // report its own accurate result instead of never running.
            Err(e) => {
                keychain_delete_failed = true;
                eprintln!("Warning: could not remove keyring entry: {e}");
            }
        }
    }

    // A parse failure here is warned about, not propagated via `?` - unlike
    // the genuinely-relevant "there might be a stale file entry we didn't
    // check" case this used to conflate with, a corrupted/unparseable file
    // says nothing about whether *this* api_url's entry was among what's
    // now unreadable, while the keychain deletion above (the primary path)
    // may have already fully succeeded for it. Propagating this as `Err`
    // made `auth::logout` print "logout may be incomplete" and "your
    // credentials might still be present" even when the credential for this
    // exact api_url was already gone - actively misleading about an
    // unrelated file-corruption problem. Degrading to a warning here
    // (matching how `load()` already handles the same kind of file error)
    // reports what's actually known to be true: the keychain result.
    let mut map = match load_file_map() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Warning: {e}");
            return keychain_delete_result(removed_something, keychain_delete_failed);
        }
    };
    if map.remove(api_url).is_none() {
        return keychain_delete_result(removed_something, keychain_delete_failed);
    }
    removed_something = true;
    // Unreachable in any realistic execution: `load_file_map()` above already
    // called `config::credentials_fallback_path()` successfully (it's how it
    // found and read the file whose in-memory copy `map.remove` just updated)
    // using the same HOME/USERPROFILE this process still has, so a second
    // call here can't newly return `None`. Kept as a defensive guard anyway,
    // since removing it would mean silently discarding a real removal - if
    // the file path genuinely couldn't be resolved, that removal can never be
    // persisted to disk, and this must surface as an error rather than
    // `Ok(())`. Silently succeeding here would tell the user "Logged out"
    // while their credentials file still has the token in it.
    let Some(path) = config::credentials_fallback_path() else {
        // `removed_something` is already `true` by this point (just above),
        // so the keychain entry for this api_url (if it had one) is already
        // gone - only the file-fallback removal is what's failing here. The
        // wording below is explicit that the on-disk entry is still present
        // (only the in-memory map was updated) rather than just "path
        // couldn't be determined", so a user who somehow hits this branch
        // isn't left conflating "path resolution failed" with "logout
        // completed" - it names the specific env var that needs setting too,
        // the same condition `load_file_map` reports as a `Config` error.
        return Err(
            "could not determine credentials file path to complete logout - \
             the file-fallback entry for this API URL is still present on \
             disk (only the in-memory copy was updated); \
             set HOME/USERPROFILE and run logout again to actually remove it"
                .to_string(),
        );
    };

    if map.is_empty() {
        match fs::remove_file(&path) {
            Ok(()) => Ok(removed_something),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(removed_something),
            Err(e) => Err(format!(
                "could not remove credentials file {}: {e}",
                path.display()
            )),
        }
    } else {
        // Other environments still have tokens in the file - rewrite it
        // (atomically, with the same 0600 permissions as a normal save)
        // instead of deleting the whole file.
        // Same zeroize-on-drop rationale, and now the same explicit-binding
        // shape, as `save_to_file`'s write path - the plain `String` from
        // `serde_json::to_string` is moved directly into `Zeroizing::new`
        // with no separate, independently-droppable binding either way, so
        // this is a consistency fix rather than a change in what's actually
        // protected.
        let json = zeroize::Zeroizing::new(
            serde_json::to_string(&map)
                .map_err(|e| format!("could not serialize remaining credentials: {e}"))?,
        );
        // Same cleanup `save_to_file` runs before its own atomic write -
        // this is the other call site that can leave a cleartext-token-
        // bearing `.tmp` file behind if the process is killed between
        // `atomic_write_secure` creating it and renaming it into place, and
        // it deserves the same treatment: nothing else in the CLI scans for
        // these left over from a killed `logout`.
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            remove_stale_credential_temp_files(dir, &path);
        }
        atomic_write_secure(&path, &json).map(|()| removed_something)
    }
}
