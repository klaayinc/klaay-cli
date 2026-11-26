// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs the built binary against a local stand-in for the GitHub release API.
//! Every command here is `login --email`, a removed flag that exits with code 2
//! before any network call. That makes it the case the banner must survive:
//! a command that ends early, with nothing on stdout.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// A home directory only this test uses, so the cache never touches the real
/// one. `dirs::config_dir()` reads a different variable on each platform.
struct Home {
    root: PathBuf,
}

impl Home {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("klaay-banner-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Home { root }
    }

    fn cache_file(&self) -> PathBuf {
        let config = if cfg!(target_os = "macos") {
            self.root.join("Library/Application Support")
        } else if cfg!(windows) {
            self.root.join("appdata")
        } else {
            self.root.join(".config")
        };
        config.join("klaay/latest-release.json")
    }

    fn seed_cache(&self, latest: &str, age_secs: u64) {
        let checked_at = now() - age_secs;
        let file = self.cache_file();
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            file,
            format!(r#"{{"checked_at":{checked_at},"latest":"{latest}"}}"#),
        )
        .unwrap();
    }

    fn run(&self, releases_url: &str, extra_env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_klaay"));
        command
            .args(["login", "--email", "someone@example.com"])
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join(".config"))
            .env("APPDATA", self.root.join("appdata"))
            .env("KLAAY_RELEASES_URL", releases_url);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command.output().expect("run klaay")
    }

    fn wait_for_cached_version(&self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if std::fs::read_to_string(self.cache_file())
                .is_ok_and(|text| text.contains(&format!("\"{expected}\"")))
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the refresh never cached {expected}");
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Serves `/releases/latest` with the tag, and counts the connections.
/// With `hang`, it accepts a connection and never answers.
fn serve_release(tag: &str, hang: bool) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/releases/latest", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let body = format!(r#"{{"tag_name":"{tag}","assets":[]}}"#);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for mut stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            if hang {
                held.push(stream);
                continue;
            }
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (url, hits)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_no_banner(output: &Output) {
    assert!(
        !stderr(output).contains("klaay upgrade"),
        "unexpected banner: {}",
        stderr(output)
    );
}

#[test]
fn a_newer_release_shows_the_banner_on_stderr_and_leaves_stdout_alone() {
    let home = Home::new("shows");
    home.seed_cache("99.0.0", 60);
    let (url, hits) = serve_release("v99.0.0", false);

    let output = home.run(&url, &[]);

    let err = stderr(&output);
    assert!(err.contains(CURRENT), "current version missing: {err}");
    assert!(err.contains("99.0.0"), "newest version missing: {err}");
    assert!(err.contains("klaay upgrade"), "command missing: {err}");
    assert!(output.stdout.is_empty(), "stdout changed");
    assert_eq!(output.status.code(), Some(2), "the command's own exit code");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a fresh cache needs no call"
    );
}

#[test]
fn the_banner_shows_when_the_command_fails() {
    let home = Home::new("fails");
    home.seed_cache("99.0.0", 60);
    let (url, _) = serve_release("v99.0.0", false);

    let output = home.run(&url, &[]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("99.0.0"), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("--email"),
        "the command's own error is kept"
    );
}

#[test]
fn no_banner_when_the_cached_release_is_not_newer() {
    for latest in [CURRENT, "0.0.1"] {
        let home = Home::new("older");
        home.seed_cache(latest, 60);
        let (url, _) = serve_release(&format!("v{latest}"), false);

        assert_no_banner(&home.run(&url, &[]));
    }
}

#[test]
fn the_opt_out_variable_turns_the_check_off() {
    let home = Home::new("optout");
    home.seed_cache("99.0.0", 60);
    let (url, hits) = serve_release("v99.0.0", false);

    let output = home.run(&url, &[("KLAAY_NO_UPDATE_CHECK", "1")]);

    assert_no_banner(&output);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn a_cold_cache_refreshes_in_the_background_and_the_next_command_shows_the_banner() {
    let home = Home::new("cold");
    let (url, _) = serve_release("v99.0.0", false);

    let first = home.run(&url, &[]);
    assert_no_banner(&first);
    home.wait_for_cached_version("99.0.0");

    let second = home.run(&url, &[]);
    assert!(stderr(&second).contains("99.0.0"), "{}", stderr(&second));
}

#[test]
fn a_stale_cache_shows_its_banner_and_refreshes() {
    let home = Home::new("stale");
    home.seed_cache("98.0.0", 3 * 24 * 60 * 60);
    let (url, _) = serve_release("v99.0.0", false);

    let output = home.run(&url, &[]);

    assert!(stderr(&output).contains("98.0.0"), "{}", stderr(&output));
    home.wait_for_cached_version("99.0.0");
}

#[test]
fn a_server_that_never_answers_neither_delays_nor_fails_the_command() {
    let home = Home::new("hang");
    let (url, hits) = serve_release("v99.0.0", true);

    let started = Instant::now();
    let first = home.run(&url, &[]);
    let elapsed = started.elapsed();

    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    assert_eq!(first.status.code(), Some(2), "the command's own exit code");
    assert_no_banner(&first);

    // The failed attempt is on record, so the next command does not try again.
    let deadline = Instant::now() + Duration::from_secs(5);
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let second = home.run(&url, &[]);
    assert_eq!(second.status.code(), Some(2));
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a second call went out");
}

#[test]
fn a_release_page_that_is_not_json_changes_nothing() {
    let home = Home::new("junk");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/releases/latest", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\njunk"
            );
        }
    });

    let output = home.run(&url, &[]);

    assert_eq!(output.status.code(), Some(2));
    assert_no_banner(&output);
}
