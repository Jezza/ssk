mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::{mode, ssk};
use predicates::prelude::*;

/// `dir` is the managed ssh dir (empty); `given` holds a key pair `handed` made with a
/// throwaway ssk, standing in for a key someone else gave us.
struct World {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    s: String,
    given: PathBuf,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("ssh");
    let given = tmp.path().join("given");
    ssk()
        .args(["--ssh-dir", given.to_str().unwrap()])
        .args(["new", "handed", "--no-passphrase", "-c", "ops@corp"])
        .assert()
        .success();
    fs::remove_file(given.join("ssk.toml")).unwrap();
    // Keys that arrive by email or download rarely keep their modes.
    fs::set_permissions(given.join("handed"), fs::Permissions::from_mode(0o644)).unwrap();
    World {
        s: dir.to_str().unwrap().to_string(),
        _tmp: tmp,
        dir,
        given,
    }
}

fn cmd(w: &World) -> assert_cmd::Command {
    let mut c = ssk();
    c.args(["--ssh-dir", &w.s]);
    c
}

fn arg(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn moves_the_pair_in_at_ssk_modes() {
    let w = world();
    let src = w.given.join("handed");
    let original = fs::read_to_string(&src).unwrap();
    let original_pub = fs::read_to_string(w.given.join("handed.pub")).unwrap();
    cmd(&w)
        .args(["import", arg(&src), "corp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported identity corp"))
        .stdout(predicate::str::contains("ops@corp"));
    assert_eq!(fs::read_to_string(w.dir.join("corp")).unwrap(), original);
    assert_eq!(
        fs::read_to_string(w.dir.join("corp.pub")).unwrap(),
        original_pub
    );
    assert_eq!(mode(&w.dir), 0o700);
    assert_eq!(mode(&w.dir.join("corp")), 0o600);
    assert_eq!(mode(&w.dir.join("corp.pub")), 0o644);
    assert!(!src.exists());
    assert!(!w.given.join("handed.pub").exists());
    cmd(&w)
        .args(["show", "corp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ops@corp"));
}

#[test]
fn keep_copies_and_leaves_the_original() {
    let w = world();
    let src = w.given.join("handed");
    cmd(&w)
        .args(["import", arg(&src), "corp", "--keep"])
        .assert()
        .success();
    assert!(w.dir.join("corp").is_file());
    assert!(w.dir.join("corp.pub").is_file());
    assert!(src.is_file());
    assert!(w.given.join("handed.pub").is_file());
    assert_eq!(mode(&src), 0o644, "the original is left exactly as it was");
}

#[test]
fn name_defaults_to_the_file_name() {
    let w = world();
    cmd(&w)
        .args(["import", arg(&w.given.join("handed"))])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported identity handed"));
    assert!(w.dir.join("handed").is_file());
}

#[test]
fn missing_pub_is_derived_from_the_private_key() {
    let w = world();
    let original_pub = fs::read_to_string(w.given.join("handed.pub")).unwrap();
    fs::remove_file(w.given.join("handed.pub")).unwrap();
    cmd(&w)
        .args(["import", arg(&w.given.join("handed")), "corp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("derive"));
    assert_eq!(
        fs::read_to_string(w.dir.join("corp.pub")).unwrap(),
        original_pub
    );
    assert_eq!(mode(&w.dir.join("corp.pub")), 0o644);
}

#[test]
fn mismatched_pub_is_refused_and_nothing_moves() {
    let w = world();
    ssk()
        .args(["--ssh-dir", arg(&w.given)])
        .args(["new", "other", "--no-passphrase"])
        .assert()
        .success();
    fs::copy(w.given.join("other.pub"), w.given.join("handed.pub")).unwrap();
    cmd(&w)
        .args(["import", arg(&w.given.join("handed")), "corp"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("does not belong to"));
    assert!(w.given.join("handed").is_file());
    assert!(!w.dir.join("corp").exists());
}

#[test]
fn existing_identity_or_state_entry_is_refused() {
    let w = world();
    cmd(&w)
        .args(["new", "corp", "--no-passphrase"])
        .assert()
        .success();
    cmd(&w)
        .args(["import", arg(&w.given.join("handed")), "corp"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    // Files gone by hand, entry left behind: the imported key must not inherit it.
    fs::remove_file(w.dir.join("corp")).unwrap();
    fs::remove_file(w.dir.join("corp.pub")).unwrap();
    cmd(&w)
        .args(["import", arg(&w.given.join("handed")), "corp"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("ssk rm corp"));
    assert!(w.given.join("handed").is_file());
}

#[test]
fn rejects_public_keys_legacy_pem_and_bad_names() {
    let w = world();
    cmd(&w)
        .args(["import", arg(&w.given.join("handed.pub"))])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("is a public key"));
    let pem = w.given.join("old");
    fs::write(
        &pem,
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    cmd(&w)
        .args(["import", arg(&pem)])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("ssh-keygen -p"));
    cmd(&w)
        .args(["import", arg(&w.given.join("handed")), "config"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("reserved"));
}

#[test]
fn dry_run_touches_nothing() {
    let w = world();
    cmd(&w)
        .args(["--dry-run", "import", arg(&w.given.join("handed")), "corp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("move "))
        .stdout(predicate::str::contains("nothing imported"));
    assert!(!w.dir.exists());
    assert!(w.given.join("handed").is_file());
}

#[test]
fn same_key_under_another_name_is_warned_about() {
    let w = world();
    let src = w.given.join("handed");
    cmd(&w)
        .args(["import", arg(&src), "corp", "--keep"])
        .assert()
        .success();
    cmd(&w)
        .args(["import", arg(&src), "corp2"])
        .assert()
        .success()
        .stderr(predicate::str::contains("same key as identity 'corp'"));
}

#[test]
fn imported_key_is_managed_and_shows_when() {
    let w = world();
    cmd(&w)
        .args(["import", arg(&w.given.join("handed")), "corp"])
        .assert()
        .success();
    let state = fs::read_to_string(w.dir.join("ssk.toml")).unwrap();
    assert!(state.contains("[identity.corp]"), "{state}");
    assert!(state.contains("imported = \""), "{state}");
    assert!(!state.contains("created"), "{state}");
    cmd(&w)
        .args(["show", "corp"])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported     20"));
    let out = cmd(&w)
        .args(["--json", "show", "corp"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v["imported"].as_str().unwrap().ends_with('Z'));
    assert_eq!(v["managed"], true);
}

#[test]
fn encrypted_key_with_its_pub_moved_gets_no_comment_warning() {
    let w = world();
    ssk()
        .args(["--ssh-dir", arg(&w.given)])
        .args(["new", "locked", "-N", "pw"])
        .assert()
        .success();
    cmd(&w)
        .args(["import", arg(&w.given.join("locked"))])
        .assert()
        .success()
        .stderr(predicate::str::contains("without a comment").not());
}
