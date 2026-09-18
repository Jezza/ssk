mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::ssk;
use predicates::prelude::*;

fn ssh_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("ssh");
    (tmp, dir)
}

fn arg(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

fn new_identity(dir: &Path, name: &str) {
    ssk()
        .args(["--ssh-dir", &arg(dir), "new", name, "--no-passphrase"])
        .assert()
        .success();
}

#[test]
fn list_shows_identities_in_a_table() {
    let (_tmp, dir) = ssh_dir();
    new_identity(&dir, "work");
    new_identity(&dir, "github");
    ssk()
        .args(["--ssh-dir", &arg(&dir), "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NAME"))
        .stdout(predicate::str::contains("work"))
        .stdout(predicate::str::contains("github"))
        .stdout(predicate::str::contains("ed25519"))
        .stdout(predicate::str::contains("n/a"));
}

#[test]
fn ls_alias_works_and_empty_dir_says_so() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no identities"));
}

#[test]
fn list_flags_broken_keys_and_points_at_doctor() {
    let (_tmp, dir) = ssh_dir();
    new_identity(&dir, "work");
    fs::write(
        dir.join("old"),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unreadable"))
        .stdout(predicate::str::contains("ssk doctor"));
}

#[test]
fn show_prints_details_and_public_key() {
    let (_tmp, dir) = ssh_dir();
    new_identity(&dir, "work");
    let pub_line = fs::read_to_string(dir.join("work.pub")).unwrap();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "show", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fingerprint  SHA256:"))
        .stdout(predicate::str::contains("mode 0600"))
        .stdout(predicate::str::contains("mode 0644"))
        .stdout(predicate::str::contains("passphrase   no"))
        .stdout(predicate::str::contains("in agent     n/a"))
        .stdout(predicate::str::contains("hosts        none recorded"))
        .stdout(predicate::str::contains("created      20"))
        .stdout(predicate::str::contains(pub_line.trim()));
}

#[test]
fn show_pub_prints_exactly_the_public_key_line() {
    let (_tmp, dir) = ssh_dir();
    new_identity(&dir, "work");
    let pub_line = fs::read_to_string(dir.join("work.pub")).unwrap();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "show", "-p", "work"])
        .assert()
        .success()
        .stdout(predicate::eq(pub_line));
}

#[test]
fn show_fingerprint_only() {
    let (_tmp, dir) = ssh_dir();
    new_identity(&dir, "work");
    ssk()
        .args(["--ssh-dir", &arg(&dir), "show", "--fingerprint", "work"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("SHA256:"))
        .stdout(predicate::str::contains('\n').count(1));
}

#[test]
fn show_unknown_identity_suggests() {
    let (_tmp, dir) = ssh_dir();
    new_identity(&dir, "github");
    ssk()
        .args(["--ssh-dir", &arg(&dir), "show", "githb"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no identity named 'githb'"))
        .stderr(predicate::str::contains("did you mean 'github'"));
}
