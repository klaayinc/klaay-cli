// SPDX-License-Identifier: GPL-3.0-or-later

//! `--email`, `--password` and `--account` signed a person in with their
//! password until v0.2.0 dropped that path. v0.1.0's README taught the flag,
//! so a script that upgrades runs straight into it. Running the built binary
//! is the only level that shows what such a script sees, because the answer
//! comes from clap's parse, not from a function this crate can call.

use std::process::Command;

fn login_with(flag: &str, value: &str) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_klaay"))
        .args(["login", flag, value])
        .output()
        .expect("run klaay login");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

#[test]
fn removed_email_flag_names_the_sign_in_that_replaced_it() {
    let (ok, text) = login_with("--email", "someone@example.com");
    assert!(!ok, "--email must fail, it signs nobody in now");
    assert!(
        text.contains("--with-token"),
        "the answer must name the path a script moves to, got: {text}"
    );
    assert!(
        text.contains("--no-browser"),
        "the answer must name the path for a machine with no browser, got: {text}"
    );
}

#[test]
fn removed_password_flag_answers_the_same_way() {
    let (ok, text) = login_with("--password", "hunter2");
    assert!(!ok, "--password must fail");
    assert!(
        text.contains("--with-token"),
        "the answer must name the path a script moves to, got: {text}"
    );
    assert!(
        !text.contains("hunter2"),
        "the answer must never echo the password back, got: {text}"
    );
}

#[test]
fn removed_account_flag_answers_the_same_way() {
    let (ok, text) = login_with("--account", "42");
    assert!(!ok, "--account must fail");
    assert!(
        text.contains("--with-token"),
        "the answer must name the path a script moves to, got: {text}"
    );
    assert!(
        text.contains("choose the account in your browser"),
        "the answer must say where the account is chosen now, got: {text}"
    );
    assert!(
        !text.contains("password"),
        "--account never carried a password, so the answer must not mention one, got: {text}"
    );
}
