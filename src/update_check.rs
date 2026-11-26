// SPDX-License-Identifier: GPL-3.0-or-later

//! The update banner. Every command reads the last answer to "what is the
//! newest release?" from a small file and prints a banner on stderr when this
//! binary is older. The network call never runs in the command's own process:
//! when the answer is a day old, the command starts `klaay
//! refresh-latest-release` and goes on. That child process outlives a command
//! that exits early, and a slow or dead network costs the command nothing.

use crate::config::{self, Config};
use crate::upgrade::{self, Version};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// GitHub allows 60 unauthenticated calls an hour per address, so one call a
/// day per machine keeps a shared address well below it.
const REFRESH_AFTER_SECS: u64 = 24 * 60 * 60;

/// Set to any non-empty value to turn the check and the banner off.
const OPT_OUT_ENV: &str = "KLAAY_NO_UPDATE_CHECK";

/// The child gives up fast. Nothing waits for it.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct Cache {
    /// When a check started, in seconds since the epoch. A check that failed
    /// still sets it, so a dead network does not start a child on every command.
    checked_at: u64,
    /// The newest stable version the last successful check found.
    latest: Option<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn banner(current: &Version, latest: &Version) -> Option<String> {
    (latest > current).then(|| {
        format!(
            "A newer klaay is out: you run {current}, the newest is {latest}.\nRun `{} upgrade` to install it.",
            config::bin_name()
        )
    })
}

fn read(path: &Path) -> Option<Cache> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn is_stale(cache: Option<&Cache>, now: u64) -> bool {
    // A check time in the future means a wrong clock: check again.
    cache.is_none_or(|c| c.checked_at > now || now - c.checked_at >= REFRESH_AFTER_SECS)
}

/// Prints the banner when the last answer is newer than this binary, and
/// starts a refresh when that answer is a day old. Never fails and never waits.
pub(crate) fn announce_and_refresh() {
    if std::env::var_os(OPT_OUT_ENV).is_some_and(|value| !value.is_empty()) {
        return;
    }
    let Some(path) = config::latest_release_cache_path() else {
        return;
    };
    let cache = read(&path);
    let latest = cache
        .as_ref()
        .and_then(|c| c.latest.as_deref())
        .and_then(Version::parse);
    if let (Some(current), Some(latest)) = (Version::parse(&crate::current_version()), latest) {
        if let Some(text) = banner(&current, &latest) {
            eprintln!("{text}");
        }
    }

    let now = now();
    if !is_stale(cache.as_ref(), now) {
        return;
    }
    let marker = Cache {
        checked_at: now,
        latest: cache.and_then(|c| c.latest),
    };
    if write(&path, &marker).is_err() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let _ = Command::new(exe)
            .arg("refresh-latest-release")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

/// The body of `klaay refresh-latest-release`. Errors end it without a word:
/// nobody reads this process's output.
pub(crate) fn refresh(config: &Config) {
    let Some(path) = config::latest_release_cache_path() else {
        return;
    };
    let url = upgrade::releases_url();
    if config.check_url_security(&url).is_err() {
        return;
    }
    let agent = upgrade::agent(REFRESH_TIMEOUT);
    let Ok(release) = upgrade::latest_release(&agent, &url) else {
        return;
    };
    let Ok(latest) = release.version() else {
        return;
    };
    let _ = write(
        &path,
        &Cache {
            checked_at: now(),
            latest: Some(latest.to_string()),
        },
    );
}

/// Writes through a temp file and a rename, so a command that reads while a
/// refresh writes never sees half a file.
fn write(path: &Path, cache: &Cache) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("the cache path has no folder"))?;
    // Owner-only, like every other folder this CLI creates under its config
    // directory (see token_store.rs).
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir)?;
    let temp = dir.join(format!("latest-release-{}.tmp", std::process::id()));
    fs::write(&temp, serde_json::to_vec(cache)?)?;
    fs::rename(&temp, path).inspect_err(|_| {
        let _ = fs::remove_file(&temp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn a_newer_release_gets_a_banner_that_names_both_versions_and_the_command() {
        let text = banner(&version("0.3.0"), &version("0.4.0")).unwrap();
        assert!(text.contains("0.3.0"), "{text}");
        assert!(text.contains("0.4.0"), "{text}");
        assert!(text.contains("upgrade"), "{text}");
    }

    #[test]
    fn the_same_or_an_older_release_gets_no_banner() {
        assert_eq!(banner(&version("0.3.0"), &version("0.3.0")), None);
        assert_eq!(banner(&version("0.3.0"), &version("0.2.0")), None);
    }

    #[test]
    fn a_nightly_gets_no_banner_for_the_stable_release_it_follows() {
        assert_eq!(
            banner(&version("0.2.0-nightly.20261120"), &version("0.2.0")),
            None
        );
    }

    #[test]
    fn a_nightly_gets_a_banner_for_the_next_stable_release() {
        assert!(banner(&version("0.2.0-nightly.20261120"), &version("0.3.0")).is_some());
    }

    fn cache(checked_at: u64) -> Cache {
        Cache {
            checked_at,
            latest: None,
        }
    }

    #[test]
    fn no_cache_is_stale() {
        assert!(is_stale(None, 1_000_000));
    }

    #[test]
    fn a_cache_is_stale_after_a_day_and_not_before() {
        let now = 1_000_000;
        assert!(!is_stale(Some(&cache(now - REFRESH_AFTER_SECS + 1)), now));
        assert!(is_stale(Some(&cache(now - REFRESH_AFTER_SECS)), now));
    }

    #[test]
    fn a_cache_from_the_future_is_stale() {
        assert!(is_stale(Some(&cache(2_000_000)), 1_000_000));
    }

    #[test]
    fn a_file_that_is_not_a_cache_reads_as_none() {
        let dir = std::env::temp_dir().join(format!("klaay-cache-unit-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("latest-release.json");
        fs::write(&path, "junk").unwrap();
        assert!(read(&path).is_none());
        write(
            &path,
            &Cache {
                checked_at: 7,
                latest: Some("1.2.3".into()),
            },
        )
        .unwrap();
        let back = read(&path).unwrap();
        assert_eq!(
            (back.checked_at, back.latest.as_deref()),
            (7, Some("1.2.3"))
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
