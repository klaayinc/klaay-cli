// SPDX-License-Identifier: GPL-3.0-or-later

//! `klaay upgrade`: finds the newest stable release on GitHub, downloads the
//! build for this machine, and replaces the running binary with it.

use crate::config::{self, Config};
use serde::Deserialize;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// GitHub's "latest release" answer excludes pre-releases, so the nightlies
/// `release.yml` publishes never reach this command.
const DEFAULT_RELEASES_URL: &str =
    "https://api.github.com/repos/klaayinc/klaay-cli/releases/latest";

/// Set to read the release from another server (a test double, a mirror).
/// The URL gets the same transport check as `--api-url`.
const RELEASES_URL_ENV: &str = "KLAAY_RELEASES_URL";

/// Far above a real release: the binary is a few megabytes. The cap stops a
/// wrong or hostile server from filling memory.
const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;

/// A release version. `0.2.0-nightly.20261120` is a build of the code that
/// comes after `v0.2.0` (see `compose_version` in main.rs), so it ranks above
/// `0.2.0` and below `0.3.0`. The derived order does this: the fields compare
/// in turn, and `None` is below `Some`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    nightly: Option<u64>,
}

impl Version {
    /// Reads `1.2.3`, `v1.2.3` and `1.2.3-nightly.20261120`. Anything else is
    /// `None`.
    pub(crate) fn parse(text: &str) -> Option<Version> {
        let text = text.strip_prefix('v').unwrap_or(text);
        let (core, nightly) = match text.split_once("-nightly.") {
            Some((core, date)) => (core, Some(number(date)?)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let version = Version {
            major: number(parts.next()?)?,
            minor: number(parts.next()?)?,
            patch: number(parts.next()?)?,
            nightly,
        };
        parts.next().is_none().then_some(version)
    }
}

fn number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        match self.nightly {
            Some(date) => write!(f, "-nightly.{date}"),
            None => Ok(()),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

impl Release {
    pub(crate) fn version(&self) -> Result<Version, String> {
        Version::parse(&self.tag_name).ok_or_else(|| {
            format!(
                "Error: the latest release has the tag \"{}\", which is not a version.",
                self.tag_name
            )
        })
    }
}

/// The release archive for one platform, as `release.yml` builds it.
#[derive(Debug, PartialEq)]
struct Build {
    os: &'static str,
    arch: &'static str,
    archive: Archive,
    /// The name of the file inside the archive.
    binary: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Archive {
    Zip,
    TarGz,
}

/// `os` and `arch` are `std::env::consts::{OS, ARCH}`. `None` means no
/// release build exists for them.
fn build_for(os: &str, arch: &str) -> Option<Build> {
    let (os, arch, archive, binary) = match (os, arch) {
        ("macos", "aarch64") => ("macOS", "arm64", Archive::Zip, "klaay"),
        ("macos", "x86_64") => ("macOS", "x64", Archive::Zip, "klaay"),
        ("linux", "x86_64") => ("Linux", "x86_64", Archive::TarGz, "klaay"),
        ("windows", "x86_64") => ("Windows", "x86_64", Archive::Zip, "klaay.exe"),
        _ => return None,
    };
    Some(Build {
        os,
        arch,
        archive,
        binary,
    })
}

impl Build {
    fn asset_name(&self, version: &Version) -> String {
        let extension = match self.archive {
            Archive::Zip => "zip",
            Archive::TarGz => "tar.gz",
        };
        format!("klaay_{version}_{}_{}.{extension}", self.os, self.arch)
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .user_agent(concat!("klaay-cli/", env!("CARGO_PKG_VERSION")))
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(120)))
            .build(),
    )
}

pub(crate) fn latest_release(agent: &ureq::Agent, url: &str) -> Result<Release, String> {
    agent
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .call()
        .and_then(|mut response| response.body_mut().read_json::<Release>())
        .map_err(|e| format!("Error: cannot read the latest release from {url}: {e}"))
}

pub(crate) fn run(config: &Config) -> Result<(), String> {
    let current_text = crate::current_version();
    let current = Version::parse(&current_text).ok_or_else(|| {
        format!("Error: cannot read the version of this binary ({current_text}).")
    })?;

    let releases_url =
        std::env::var(RELEASES_URL_ENV).unwrap_or_else(|_| DEFAULT_RELEASES_URL.to_string());
    config.check_url_security(&releases_url)?;
    let agent = agent();
    let release = latest_release(&agent, &releases_url)?;
    let latest = release.version()?;

    if current == latest {
        println!("klaay {current} is already the newest release. Nothing changed.");
        return Ok(());
    }
    if current > latest {
        println!("klaay {current} is newer than the latest release ({latest}). Nothing changed.");
        return Ok(());
    }

    let build = build_for(std::env::consts::OS, std::env::consts::ARCH).ok_or_else(|| {
        format!(
            "Error: release {latest} has no download for this platform ({} {}).",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let asset_name = build.asset_name(&latest);
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| {
            format!("Error: release {latest} has no download for this platform ({asset_name} is missing).")
        })?;
    config.check_url_security(&asset.browser_download_url)?;

    let exe = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|e| format!("Error: cannot find this binary on disk: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| format!("Error: {} has no parent folder.", exe.display()))?;

    // Created before the download, so a folder this user cannot write to fails
    // now instead of after several megabytes.
    let (staged, mut file) = stage(dir, &exe)?;
    let archive = download(&agent, &asset.browser_download_url)?;
    let binary = extract_binary(&archive, &build)?;
    file.write_all(&binary)
        .and_then(|()| file.flush())
        .map_err(|e| write_error(&e, dir, &exe))?;
    // Windows cannot copy a file that is still open.
    drop(file);
    swap(&staged.0, &exe).map_err(|e| write_error(&e, dir, &exe))?;

    println!("Upgraded klaay from {current} to {latest}.");
    Ok(())
}

/// Puts the staged file in place of the running binary. The running process
/// keeps its own copy of the old file, so the swap does not stop it.
#[cfg(not(windows))]
fn swap(staged: &Path, exe: &Path) -> io::Result<()> {
    // Same folder, so the rename is atomic: a reader sees the old binary or
    // the new one, never half of one.
    fs::set_permissions(staged, fs::metadata(exe)?.permissions())?;
    fs::rename(staged, exe)
}

/// Windows refuses to overwrite a running .exe. `self_replace` moves the old
/// file aside, puts the new one in its place and removes the old one later.
#[cfg(windows)]
fn swap(staged: &Path, _exe: &Path) -> io::Result<()> {
    self_replace::self_replace(staged)
}

/// A file next to the running binary that holds the new one until the swap.
/// Dropping it removes the file, on success and on every error.
struct Staged(PathBuf);

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn stage(dir: &Path, exe: &Path) -> Result<(Staged, File), String> {
    let path = dir.join(format!(".klaay-upgrade-{}.tmp", std::process::id()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| write_error(&e, dir, exe))?;
    Ok((Staged(path), file))
}

/// The message for a failed write next to the binary. The common cause is a
/// binary in a folder only an administrator can write, such as /usr/local/bin.
fn write_error(error: &io::Error, dir: &Path, exe: &Path) -> String {
    if !matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
    ) {
        return format!("Error: cannot replace {}: {error}", exe.display());
    }
    let bin = config::bin_name();
    let fix = if cfg!(windows) {
        format!("Start a terminal as administrator and run `{bin} upgrade` again, or install klaay in a folder you own.")
    } else {
        format!("Run `sudo {bin} upgrade`, or install klaay in a directory you own.")
    };
    format!(
        "Error: klaay cannot write to {}, so it cannot replace {}.\n{fix}",
        dir.display(),
        exe.display()
    )
}

fn download(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, String> {
    agent
        .get(url)
        .call()
        .and_then(|mut response| {
            response
                .body_mut()
                .with_config()
                .limit(MAX_DOWNLOAD_BYTES)
                .read_to_vec()
        })
        .map_err(|e| format!("Error: cannot download {url}: {e}"))
}

/// Pulls the binary out of the release archive: the one file whose name is
/// `build.binary`, wherever it sits in the archive.
fn extract_binary(archive: &[u8], build: &Build) -> Result<Vec<u8>, String> {
    let found = match build.archive {
        Archive::Zip => {
            let mut zip = zip::ZipArchive::new(Cursor::new(archive))
                .map_err(|e| format!("Error: the download is not a zip file: {e}"))?;
            let mut found = None;
            for index in 0..zip.len() {
                let entry = zip
                    .by_index(index)
                    .map_err(|e| format!("Error: cannot read the zip file: {e}"))?;
                if entry.is_file()
                    && entry
                        .name()
                        .is_ok_and(|name| has_file_name(&name, build.binary))
                {
                    found = Some(read_limited(entry)?);
                    break;
                }
            }
            found
        }
        Archive::TarGz => {
            let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
            let mut found = None;
            let entries = tar
                .entries()
                .map_err(|e| format!("Error: the download is not a tar.gz file: {e}"))?;
            for entry in entries {
                let entry =
                    entry.map_err(|e| format!("Error: cannot read the tar.gz file: {e}"))?;
                let path = entry
                    .path()
                    .map_err(|e| format!("Error: cannot read the tar.gz file: {e}"))?
                    .to_string_lossy()
                    .into_owned();
                if entry.header().entry_type().is_file() && has_file_name(&path, build.binary) {
                    found = Some(read_limited(entry)?);
                    break;
                }
            }
            found
        }
    };
    found.ok_or_else(|| format!("Error: the download holds no file named {}.", build.binary))
}

fn has_file_name(path: &str, name: &str) -> bool {
    path.rsplit(['/', '\\']).next() == Some(name)
}

fn read_limited(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BINARY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Error: cannot unpack the download: {e}"))?;
    if bytes.len() as u64 > MAX_BINARY_BYTES {
        return Err("Error: the binary in the download is too large.".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} should parse"))
    }

    #[test]
    fn reads_a_stable_version_with_or_without_the_tag_prefix() {
        assert_eq!(version("0.3.0"), version("v0.3.0"));
        assert_eq!(version("v0.3.0").to_string(), "0.3.0");
    }

    #[test]
    fn reads_a_nightly_version() {
        assert_eq!(
            version("0.2.0-nightly.20261120").to_string(),
            "0.2.0-nightly.20261120"
        );
    }

    #[test]
    fn rejects_text_that_is_not_a_version() {
        for text in [
            "",
            "v",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1.2.3-beta.1",
            "1.2.3-nightly.",
            "1.2.3-nightly.x",
            "-1.2.3",
            "latest",
        ] {
            assert_eq!(Version::parse(text), None, "{text}");
        }
    }

    #[test]
    fn compares_numbers_not_text() {
        assert!(version("0.10.0") > version("0.9.0"));
        assert!(version("1.0.0") > version("0.99.99"));
    }

    #[test]
    fn a_nightly_ranks_above_the_stable_it_follows() {
        assert!(version("0.2.0-nightly.20261120") > version("0.2.0"));
    }

    #[test]
    fn a_nightly_ranks_below_the_next_stable() {
        assert!(version("0.2.0-nightly.20261120") < version("0.3.0"));
    }

    #[test]
    fn a_later_nightly_ranks_above_an_earlier_one() {
        assert!(version("0.2.0-nightly.20261121") > version("0.2.0-nightly.20261120"));
    }

    #[test]
    fn names_the_asset_of_each_release_platform() {
        let v = version("0.3.0");
        let names: Vec<String> = [
            ("macos", "aarch64"),
            ("macos", "x86_64"),
            ("linux", "x86_64"),
            ("windows", "x86_64"),
        ]
        .into_iter()
        .map(|(os, arch)| build_for(os, arch).unwrap().asset_name(&v))
        .collect();
        assert_eq!(
            names,
            [
                "klaay_0.3.0_macOS_arm64.zip",
                "klaay_0.3.0_macOS_x64.zip",
                "klaay_0.3.0_Linux_x86_64.tar.gz",
                "klaay_0.3.0_Windows_x86_64.zip",
            ]
        );
    }

    #[test]
    fn windows_asks_for_the_exe_inside_the_archive() {
        assert_eq!(build_for("windows", "x86_64").unwrap().binary, "klaay.exe");
        assert_eq!(build_for("linux", "x86_64").unwrap().binary, "klaay");
    }

    #[test]
    fn no_build_exists_for_other_platforms() {
        assert_eq!(build_for("linux", "aarch64"), None);
        assert_eq!(build_for("windows", "aarch64"), None);
        assert_eq!(build_for("freebsd", "x86_64"), None);
    }

    fn zip_with(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in files {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(body).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn tar_gz_with(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, name, *body).unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar.into_inner().unwrap()).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn unpacks_the_binary_from_a_zip() {
        let archive = zip_with(&[("README", b"read me"), ("klaay", b"binary")]);
        let build = build_for("macos", "aarch64").unwrap();
        assert_eq!(extract_binary(&archive, &build).unwrap(), b"binary");
    }

    #[test]
    fn unpacks_the_exe_from_a_windows_zip() {
        let archive = zip_with(&[("klaay.exe", b"binary")]);
        let build = build_for("windows", "x86_64").unwrap();
        assert_eq!(extract_binary(&archive, &build).unwrap(), b"binary");
    }

    #[test]
    fn unpacks_the_binary_from_a_tar_gz() {
        let archive = tar_gz_with(&[("LICENSE", b"text"), ("klaay", b"binary")]);
        let build = build_for("linux", "x86_64").unwrap();
        assert_eq!(extract_binary(&archive, &build).unwrap(), b"binary");
    }

    #[test]
    fn an_archive_without_the_binary_is_an_error() {
        let build = build_for("linux", "x86_64").unwrap();
        let error = extract_binary(&tar_gz_with(&[("other", b"x")]), &build).unwrap_err();
        assert!(error.contains("no file named klaay"), "{error}");
        let build = build_for("macos", "aarch64").unwrap();
        let error = extract_binary(&zip_with(&[("other", b"x")]), &build).unwrap_err();
        assert!(error.contains("no file named klaay"), "{error}");
    }

    #[test]
    fn bytes_that_are_not_an_archive_are_an_error() {
        let zip_build = build_for("macos", "aarch64").unwrap();
        assert!(extract_binary(b"not a zip", &zip_build).is_err());
        let tar_build = build_for("linux", "x86_64").unwrap();
        assert!(extract_binary(b"not a tar", &tar_build).is_err());
    }

    #[test]
    fn matches_a_file_name_inside_a_folder_but_not_a_longer_name() {
        assert!(has_file_name("klaay", "klaay"));
        assert!(has_file_name("dist/klaay", "klaay"));
        assert!(has_file_name("dist\\klaay.exe", "klaay.exe"));
        assert!(!has_file_name("klaay.sig", "klaay"));
        assert!(!has_file_name("not-klaay", "klaay"));
    }

    #[test]
    fn a_permission_error_names_the_fix() {
        let error = io::Error::from(io::ErrorKind::PermissionDenied);
        let message = write_error(
            &error,
            Path::new("/usr/local/bin"),
            Path::new("/usr/local/bin/klaay"),
        );
        assert!(
            message.contains("cannot write to /usr/local/bin"),
            "{message}"
        );
        assert!(message.contains("sudo") || cfg!(windows), "{message}");
    }

    #[test]
    fn another_error_keeps_its_own_cause() {
        let error = io::Error::other("disk on fire");
        let message = write_error(&error, Path::new("/bin"), Path::new("/bin/klaay"));
        assert!(message.contains("disk on fire"), "{message}");
        assert!(!message.contains("sudo"), "{message}");
    }
}
