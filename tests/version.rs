// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs the built binary, so it holds the whole `--version` chain: the clap
//! `version =` attribute, the `string` feature it needs, and the
//! `option_env!` plumbing. The test and the binary compile in the same cargo
//! invocation, so both see the same `KLAAY_VERSION_SUFFIX` - the assertion
//! is exact with and without a suffix.

use std::process::Command;

#[test]
fn version_flag_reports_the_composed_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_klaay"))
        .arg("--version")
        .output()
        .expect("run klaay --version");
    assert!(output.status.success());
    let expected = format!(
        "klaay {}{}\n",
        env!("CARGO_PKG_VERSION"),
        option_env!("KLAAY_VERSION_SUFFIX").unwrap_or("")
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
}
