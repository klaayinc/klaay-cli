// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs a copy of the built binary against a local stand-in for the GitHub
//! release API, so the whole `klaay upgrade` path runs for real: the release
//! lookup, the download, the unpack and the in-place swap. The copy lives in
//! its own temp directory, so the swap never touches the binary cargo built.
//! The tests run on the platforms the release workflow ships.

#![cfg(any(
    all(
        target_os = "macos",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ),
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86_64")
))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CURRENT: &str = env!("CARGO_PKG_VERSION");
const NEW_VERSION: &str = "99.0.0";
const NEW_BINARY: &[u8] = b"#!/bin/sh\necho klaay 99.0.0\n";

/// The asset this platform's release carries, as `release.yml` names it.
fn asset_name(version: &str) -> String {
    let (os, arch, ext) = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        ("macOS", "arm64", "zip")
    } else if cfg!(target_os = "macos") {
        ("macOS", "x64", "zip")
    } else if cfg!(target_os = "linux") {
        ("Linux", "x86_64", "tar.gz")
    } else {
        ("Windows", "x86_64", "zip")
    };
    format!("klaay_{version}_{os}_{arch}.{ext}")
}

/// The archive `release.yml` builds: the bare binary, nothing else.
fn archive_bytes() -> Vec<u8> {
    if cfg!(target_os = "linux") {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(NEW_BINARY.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "klaay", NEW_BINARY).unwrap();
        let tar_bytes = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    } else {
        let name = if cfg!(windows) { "klaay.exe" } else { "klaay" };
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(NEW_BINARY).unwrap();
        zip.finish().unwrap().into_inner()
    }
}

/// Answers `/releases/latest` with a release that names `tag`, and
/// `/download/<asset>` with the archive. Returns the releases URL.
fn serve_release(tag: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let version = tag.trim_start_matches('v');
    let release = format!(
        r#"{{"tag_name":"{tag}","prerelease":false,"assets":[
            {{"name":"klaay_{version}_Windows_x86_64.zip","browser_download_url":"{base}/download/wrong"}},
            {{"name":"{name}","browser_download_url":"{base}/download/{name}"}}]}}"#,
        name = asset_name(version)
    );
    let archive = archive_bytes();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            answer(stream, &release, &archive);
        }
    });
    format!("{base}/releases/latest")
}

fn answer(mut stream: TcpStream, release: &str, archive: &[u8]) {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    let request = String::from_utf8_lossy(&request);
    let path = request.split_whitespace().nth(1).unwrap_or("");
    let (status, body): (&str, &[u8]) = if path == "/releases/latest" {
        ("200 OK", release.as_bytes())
    } else if path.starts_with("/download/klaay_") {
        ("200 OK", archive)
    } else {
        ("404 Not Found", b"not found")
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// A copy of the built binary in a fresh directory that only this test uses.
struct InstalledCopy {
    dir: PathBuf,
    binary: PathBuf,
}

impl InstalledCopy {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("klaay-upgrade-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join(if cfg!(windows) { "klaay.exe" } else { "klaay" });
        std::fs::copy(env!("CARGO_BIN_EXE_klaay"), &binary).unwrap();
        InstalledCopy { dir, binary }
    }

    fn upgrade(&self, releases_url: &str) -> Output {
        Command::new(&self.binary)
            .arg("upgrade")
            .env("KLAAY_RELEASES_URL", releases_url)
            .output()
            .expect("run klaay upgrade")
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.binary).unwrap()
    }

    fn leftovers(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for InstalledCopy {
    fn drop(&mut self) {
        restore_write_access(&self.dir);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn restore_write_access(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn restore_write_access(_dir: &Path) {}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_newer_release_replaces_the_binary_and_names_both_versions() {
    let installed = InstalledCopy::new("replace");
    let before = installed.bytes();
    let url = serve_release(&format!("v{NEW_VERSION}"));

    let output = installed.upgrade(&url);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains(CURRENT), "old version missing: {out}");
    assert!(out.contains(NEW_VERSION), "new version missing: {out}");
    assert_ne!(installed.bytes(), before);
    assert_eq!(installed.bytes(), NEW_BINARY);
    // Windows keeps the old binary aside until the process ends.
    #[cfg(unix)]
    assert_eq!(
        installed.leftovers().len(),
        1,
        "a temporary file stayed behind: {:?}",
        installed.leftovers()
    );
}

#[cfg(unix)]
#[test]
fn the_replaced_binary_runs_and_keeps_its_execute_permission() {
    let installed = InstalledCopy::new("runs");
    let url = serve_release(&format!("v{NEW_VERSION}"));
    assert!(installed.upgrade(&url).status.success());

    let output = Command::new(&installed.binary)
        .arg("--version")
        .output()
        .expect("run the replaced binary");

    assert_eq!(stdout(&output), format!("klaay {NEW_VERSION}\n"));
}

/// Homebrew and similar installers put a relative symlink on the PATH that
/// points at the real binary.
#[cfg(unix)]
#[test]
fn a_binary_started_through_a_relative_symlink_is_replaced_in_place() {
    let installed = InstalledCopy::new("symlink");
    let bin_dir = installed.dir.join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let link = bin_dir.join("klaay");
    std::os::unix::fs::symlink("../klaay", &link).unwrap();
    let url = serve_release(&format!("v{NEW_VERSION}"));

    let output = Command::new(&link)
        .arg("upgrade")
        .env("KLAAY_RELEASES_URL", &url)
        .current_dir("/")
        .output()
        .expect("run klaay upgrade through the symlink");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(installed.bytes(), NEW_BINARY);
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        Path::new("../klaay"),
        "the symlink must stay a symlink"
    );
}

#[test]
fn the_newest_release_changes_nothing_and_says_so() {
    let installed = InstalledCopy::new("same");
    let before = installed.bytes();
    let url = serve_release(&format!("v{CURRENT}"));

    let output = installed.upgrade(&url);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("already the newest release"),
        "{}",
        stdout(&output)
    );
    assert!(stdout(&output).contains(CURRENT));
    assert_eq!(installed.bytes(), before);
    assert_eq!(
        installed.leftovers().len(),
        1,
        "{:?}",
        installed.leftovers()
    );
}

#[test]
fn an_older_release_changes_nothing_and_says_the_binary_is_newer() {
    let installed = InstalledCopy::new("older");
    let before = installed.bytes();
    let url = serve_release("v0.0.1");

    let output = installed.upgrade(&url);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("newer than the latest release"),
        "{}",
        stdout(&output)
    );
    assert_eq!(installed.bytes(), before);
}

#[cfg(unix)]
#[test]
fn a_directory_without_write_access_says_so_and_names_the_fix() {
    use std::os::unix::fs::PermissionsExt;
    let installed = InstalledCopy::new("readonly");
    std::fs::set_permissions(&installed.dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    if std::fs::File::create(installed.dir.join("probe")).is_ok() {
        // Running as root: a read-only directory still accepts writes.
        return;
    }
    let before = installed.bytes();
    let url = serve_release(&format!("v{NEW_VERSION}"));

    let output = installed.upgrade(&url);

    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("cannot write"), "{err}");
    assert!(err.contains(&installed.dir.display().to_string()), "{err}");
    assert!(err.contains("sudo"), "{err}");
    assert_eq!(installed.bytes(), before);
}

#[test]
fn a_release_without_an_asset_for_this_platform_says_so() {
    let installed = InstalledCopy::new("noasset");
    let before = installed.bytes();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/releases/latest", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = r#"{"tag_name":"v99.0.0","assets":[]}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });

    let output = installed.upgrade(&url);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("no download for this platform"));
    assert_eq!(installed.bytes(), before);
}
