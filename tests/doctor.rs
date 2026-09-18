mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use common::ssk;
use predicates::prelude::*;

fn ssh_dir() -> (tempfile::TempDir, PathBuf, String) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("ssh");
    let s = dir.to_str().unwrap().to_string();
    ssk()
        .args(["--ssh-dir", &s, "new", "work", "--no-passphrase"])
        .assert()
        .success();
    (tmp, dir, s)
}

#[test]
fn doctor_is_quiet_and_zero_on_a_healthy_dir() {
    let (_tmp, _dir, s) = ssh_dir();
    ssk()
        .args(["--ssh-dir", &s, "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("looks healthy"));
}

#[test]
fn doctor_reports_fixes_and_then_passes() {
    let (_tmp, dir, s) = ssh_dir();
    fs::set_permissions(dir.join("work.pub"), fs::Permissions::from_mode(0o666)).unwrap();

    ssk()
        .args(["--ssh-dir", &s, "doctor"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("pub-writable"))
        .stdout(predicate::str::contains("[fixable]"))
        .stdout(predicate::str::contains("ssk doctor --fix"));

    ssk()
        .args(["--ssh-dir", &s, "doctor", "--fix"])
        .assert()
        .success()
        .stdout(predicate::str::contains("chmod 0644"))
        .stdout(predicate::str::contains("applied 1 fix"));

    ssk().args(["--ssh-dir", &s, "doctor"]).assert().success();
}

#[test]
fn doctor_dry_run_fix_changes_nothing() {
    let (_tmp, dir, s) = ssh_dir();
    fs::set_permissions(dir.join("work.pub"), fs::Permissions::from_mode(0o666)).unwrap();
    ssk()
        .args(["--ssh-dir", &s, "--dry-run", "doctor", "--fix"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("dry run"));
    assert_eq!(
        fs::metadata(dir.join("work.pub"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o666
    );
}
