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
