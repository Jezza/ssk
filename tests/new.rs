mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{mode, ssk};
use predicates::prelude::*;

fn ssh_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("ssh");
    (tmp, dir)
}

fn arg(p: &Path) -> String {
    p.to_str().unwrap().to_string()
}

#[test]
fn creates_ed25519_pair_with_modes_and_state() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "new", "work", "--no-passphrase"])
        .assert()
        .success()
        .stdout(predicate::str::contains("created identity work"))
        .stdout(predicate::str::contains("SHA256:"))
        .stdout(predicate::str::contains("ssh-ed25519 "))
        .stderr(predicate::str::contains("without a passphrase"));
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("work")), 0o600);
    assert_eq!(mode(&dir.join("work.pub")), 0o644);
    let key = ssh_key::PrivateKey::read_openssh_file(&dir.join("work")).unwrap();
    assert!(!key.is_encrypted());
    assert_eq!(key.algorithm(), ssh_key::Algorithm::Ed25519);
    let state = fs::read_to_string(dir.join("ssk.toml")).unwrap();
    assert!(state.contains("[identity.work]"), "{state}");
    assert!(state.contains("created = \""), "{state}");
}

#[test]
fn default_comment_is_identity_at_hostname() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "new", "work", "--no-passphrase"])
        .assert()
        .success();
    let pub_line = fs::read_to_string(dir.join("work.pub")).unwrap();
    let comment = pub_line.trim().splitn(3, ' ').nth(2).unwrap_or("");
    assert!(comment.starts_with("work@"), "{pub_line}");
}

#[test]
fn custom_comment_is_used() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args([
            "--ssh-dir",
            &arg(&dir),
            "new",
            "work",
            "--no-passphrase",
            "-c",
            "hello there",
        ])
        .assert()
        .success();
    assert!(
        fs::read_to_string(dir.join("work.pub"))
            .unwrap()
            .trim()
            .ends_with(" hello there")
    );
}

#[test]
fn passphrase_flag_encrypts() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "new", "vault", "-N", "s3cret"])
        .assert()
        .success();
    let key = ssh_key::PrivateKey::read_openssh_file(&dir.join("vault")).unwrap();
    assert!(key.is_encrypted());
    assert!(key.decrypt("s3cret").is_ok());
}

#[test]
fn passphrase_from_stdin() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args([
            "--ssh-dir",
            &arg(&dir),
            "new",
            "vault",
            "--passphrase-stdin",
        ])
        .write_stdin("fromstdin\n")
        .assert()
        .success();
    let key = ssh_key::PrivateKey::read_openssh_file(&dir.join("vault")).unwrap();
    assert!(key.decrypt("fromstdin").is_ok());
}

#[test]
fn no_terminal_and_no_passphrase_flag_is_a_clear_error() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args(["--ssh-dir", &arg(&dir), "new", "work"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no terminal"));
    assert!(!dir.join("work").exists());
}

#[test]
fn refuses_to_overwrite_without_force_and_overwrites_with_force_yes() {
    let (_tmp, dir) = ssh_dir();
    let d = arg(&dir);
    ssk()
        .args(["--ssh-dir", &d, "new", "work", "--no-passphrase"])
        .assert()
        .success();
    let before = fs::read(dir.join("work.pub")).unwrap();

    ssk()
        .args(["--ssh-dir", &d, "new", "work", "--no-passphrase"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));

    // --force without --yes and without a terminal: refuse rather than guess
    ssk()
        .args(["--ssh-dir", &d, "new", "work", "--no-passphrase", "--force"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--yes"));
    assert_eq!(fs::read(dir.join("work.pub")).unwrap(), before);

    ssk()
        .args([
            "--ssh-dir",
            &d,
            "-y",
            "new",
            "work",
            "--no-passphrase",
            "--force",
        ])
        .assert()
        .success();
    assert_ne!(fs::read(dir.join("work.pub")).unwrap(), before);
}

#[test]
fn rejects_bits_for_ed25519_and_reserved_names_before_touching_disk() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args([
            "--ssh-dir",
            &arg(&dir),
            "new",
            "work",
            "--no-passphrase",
            "-b",
            "256",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not applicable"));
    ssk()
        .args(["--ssh-dir", &arg(&dir), "new", "config", "--no-passphrase"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("reserved"));
    assert!(!dir.exists());
}

#[test]
fn ecdsa_with_bits() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args([
            "--ssh-dir",
            &arg(&dir),
            "new",
            "e",
            "--no-passphrase",
            "-t",
            "ecdsa",
            "-b",
            "384",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ecdsa 384"));
}

#[test]
fn dry_run_writes_nothing() {
    let (_tmp, dir) = ssh_dir();
    ssk()
        .args([
            "--ssh-dir",
            &arg(&dir),
            "--dry-run",
            "new",
            "work",
            "--no-passphrase",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("would generate"));
    assert!(!dir.exists());
}
