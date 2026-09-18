mod common;

use std::fs;
use std::path::PathBuf;

use common::{fake_ssh, ssk};
use predicates::prelude::*;

struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    dir: PathBuf,
    s: String,
    fake: PathBuf,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let dir = root.join("ssh");
    let s = dir.to_str().unwrap().to_string();
    ssk()
        .args(["--ssh-dir", &s, "new", "work", "--no-passphrase"])
        .assert()
        .success();
    let fake = fake_ssh(&root);
    World {
        _tmp: tmp,
        root,
        dir,
        s,
        fake,
    }
}

fn cmd(w: &World) -> assert_cmd::Command {
    let mut c = ssk();
    c.env("SSK_SSH_BIN", &w.fake)
        .env("FAKE_SSH_DIR", &w.root)
        .args(["--ssh-dir", &w.s]);
    c
}

fn authorized_keys(w: &World, host: &str) -> String {
    fs::read_to_string(w.root.join(format!("home-{host}/.ssh/authorized_keys"))).unwrap_or_default()
}

fn blob(w: &World, name: &str) -> String {
    let line = fs::read_to_string(w.dir.join(format!("{name}.pub"))).unwrap();
    line.split_whitespace().nth(1).unwrap().to_string()
}

fn deployed(w: &World) {
    cmd(w)
        .args(["copy", "work", "deploy@a.test", "b.test:2222"])
        .assert()
        .success();
}

#[test]
fn rotate_installs_revokes_and_swaps() {
    let w = world();
    deployed(&w);
    let old = blob(&w, "work");
    cmd(&w)
        .args(["-y", "rotate", "work", "--no-passphrase"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new key installed and verified"))
        .stdout(predicate::str::contains("old key removed and verified"))
        .stdout(predicate::str::contains("rotated identity work"));
    let new = blob(&w, "work");
    assert_ne!(old, new);
    for host in ["a.test", "b.test"] {
        let ak = authorized_keys(&w, host);
        assert!(ak.contains(&new) && !ak.contains(&old), "{host}:\n{ak}");
        assert_eq!(ak.lines().count(), 1, "{host}:\n{ak}");
    }
    for leftover in ["work.new", "work.new.pub", "work.old", "work.old.pub"] {
        assert!(!w.dir.join(leftover).exists(), "{leftover} should be gone");
    }
    let state = fs::read_to_string(w.dir.join("ssk.toml")).unwrap();
    assert_eq!(
        state.matches("[[identity.work.deployments]]").count(),
        2,
        "{state}"
    );
    assert!(
        !state.contains("work.old") && !state.contains("work.new"),
        "{state}"
    );
    cmd(&w)
        .args(["show", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("a.test"));
}

#[test]
fn rotate_stops_before_revoking_when_a_host_is_down_then_resumes() {
    let w = world();
    deployed(&w);
    let old = blob(&w, "work");
    cmd(&w)
        .env("FAKE_SSH_FAIL_HOST", "b.test")
        .args(["-y", "rotate", "work", "--no-passphrase"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not rotated"))
        .stdout(predicate::str::contains("re-run `ssk rotate work`"));
    assert!(w.dir.join("work.new").exists());
    assert_eq!(blob(&w, "work"), old, "the live key is unchanged");
    let staged = blob(&w, "work.new");
    let a = authorized_keys(&w, "a.test");
    assert!(
        a.contains(&old) && a.contains(&staged),
        "nothing revoked yet:\n{a}"
    );
    assert!(!authorized_keys(&w, "b.test").contains(&staged));

    cmd(&w)
        .args(["-y", "rotate", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("reuse the existing work.new"))
        // the install step is forced, so a.test is installed again (idempotently) rather
        // than skipped on the probe's say-so
        .stdout(predicate::str::contains(
            "a.test: new key installed and verified",
        ));
    assert_eq!(blob(&w, "work"), staged);
    for host in ["a.test", "b.test"] {
        let ak = authorized_keys(&w, host);
        assert!(ak.contains(&staged) && !ak.contains(&old), "{host}:\n{ak}");
    }
    assert!(!w.dir.join("work.new").exists());
}

#[test]
fn rotate_keeps_the_old_key_when_a_revoke_fails() {
    let w = world();
    deployed(&w);
    let old = blob(&w, "work");
    cmd(&w)
        .env("FAKE_SSH_FAIL_REVOKE", "1")
        .args(["-y", "rotate", "work", "--no-passphrase"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("old key kept as work.old"))
        .stdout(predicate::str::contains("ssk revoke work.old --all"));
    assert_ne!(blob(&w, "work"), old, "the swap still happened");
    assert_eq!(blob(&w, "work.old"), old);
    let state = fs::read_to_string(w.dir.join("ssk.toml")).unwrap();
    assert!(
        state.contains("[identity.\"work.old\"]") || state.contains("[identity.work.old]"),
        "{state}"
    );
    assert_eq!(
        state
            .matches("[[identity.\"work.old\".deployments]]")
            .count()
            + state.matches("[[identity.work.old.deployments]]").count(),
        2,
        "{state}"
    );

    // A lingering `work.old` must block a second rotation, rather than being silently
    // clobbered by it.
    cmd(&w)
        .args(["-y", "rotate", "work", "--no-passphrase"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("work.old"))
        .stderr(predicate::str::contains("ssk revoke work.old --all"));
    assert_eq!(
        blob(&w, "work.old"),
        old,
        "the lingering .old key is untouched"
    );
    assert!(!w.dir.join("work.new").exists(), "no new key was generated");

    cmd(&w)
        .args(["revoke", "work.old", "--all"])
        .assert()
        .success();
    cmd(&w).args(["-y", "rm", "work.old"]).assert().success();
    assert!(!w.dir.join("work.old").exists());
}

#[test]
fn rotate_without_deployments_only_swaps_locally() {
    let w = world();
    let old = blob(&w, "work");
    cmd(&w)
        .args(["-y", "rotate", "work", "--no-passphrase"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no deployments recorded"));
    assert_ne!(blob(&w, "work"), old);
    assert!(!w.root.join("args.log").exists(), "no ssh calls");
}

#[test]
fn rotate_dry_run_and_refusal_touch_nothing() {
    let w = world();
    deployed(&w);
    cmd(&w)
        .args(["--dry-run", "rotate", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would run"))
        .stdout(predicate::str::contains("dry run: nothing generated"));
    assert!(!w.dir.join("work.new").exists());
    cmd(&w)
        .args(["rotate", "work", "--no-passphrase"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no terminal"));
    assert!(!w.dir.join("work.new").exists());
    let log = fs::read_to_string(w.root.join("args.log")).unwrap();
    assert_eq!(log.lines().count(), 6, "only the two copies ran:\n{log}");
}

#[test]
fn rotate_to_rsa_without_a_size_uses_rsa_bits() {
    let w = world();
    cmd(&w)
        .env("SSK_RSA_BITS", "2048")
        .args(["-y", "rotate", "work", "--no-passphrase", "-t", "rsa"])
        .assert()
        .success();
    cmd(&w)
        .args(["show", "work"])
        .assert()
        .stdout(predicate::str::contains("rsa 2048"));
}

#[test]
fn rotate_honours_type_override_and_keeps_comment() {
    let w = world();
    cmd(&w)
        .args(["-y", "rotate", "work", "--no-passphrase", "-t", "ecdsa"])
        .assert()
        .success();
    cmd(&w)
        .args(["show", "work"])
        .assert()
        .stdout(predicate::str::contains("ecdsa 256"))
        .stdout(predicate::str::contains("work@"));
}
