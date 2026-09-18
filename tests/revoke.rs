mod common;

use std::fs;
use std::path::PathBuf;

use common::{fake_ssh, ssk, unreachable_ssh};
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

fn state(w: &World) -> String {
    fs::read_to_string(w.dir.join("ssk.toml")).unwrap_or_default()
}

#[test]
fn revoke_removes_verifies_and_forgets() {
    let w = world();
    cmd(&w)
        .args(["copy", "work", "deploy@a.test:2222"])
        .assert()
        .success();
    assert!(authorized_keys(&w, "a.test").contains(&blob(&w, "work")));
    assert!(w.dir.join("ssk.d/work.conf").exists());

    cmd(&w)
        .args(["revoke", "work", "deploy@a.test:2222"])
        .assert()
        .success()
        .stdout(predicate::str::contains("revoked and verified"))
        .stdout(predicate::str::contains("ssh config removed"));
    assert!(!authorized_keys(&w, "a.test").contains(&blob(&w, "work")));
    assert!(!state(&w).contains("deployments"), "{}", state(&w));
    assert!(!w.dir.join("ssk.d/work.conf").exists());

    let log = fs::read_to_string(w.root.join("args.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 5, "{log}");
    assert!(
        lines[3].contains(&format!("-i {}/work", w.s)),
        "{}",
        lines[3]
    );
    assert!(lines[3].contains("-p 2222 -l deploy"), "{}", lines[3]);
    assert!(lines[3].contains("exec sh -c '"), "{}", lines[3]);
    assert!(lines[4].ends_with("-- a.test exit"), "{}", lines[4]);
}

#[test]
fn revoke_where_never_installed_is_not_present() {
    let w = world();
    cmd(&w)
        .args(["revoke", "work", "b.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not present"));
}

#[test]
fn revoke_all_uses_recorded_hosts_and_needs_some() {
    let w = world();
    cmd(&w)
        .args(["revoke", "work", "--all"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no deployments recorded"));
    cmd(&w)
        .args(["copy", "work", "a.test", "b.test"])
        .assert()
        .success();
    cmd(&w).args(["revoke", "work", "--all"]).assert().success();
    for h in ["a.test", "b.test"] {
        assert!(!authorized_keys(&w, h).contains(&blob(&w, "work")), "{h}");
    }
    assert!(!state(&w).contains("deployments"));
}

#[test]
fn revoke_from_one_host_keeps_the_others_config() {
    let w = world();
    cmd(&w)
        .args(["copy", "work", "a.test", "b.test"])
        .assert()
        .success();
    cmd(&w)
        .args(["revoke", "work", "a.test"])
        .assert()
        .success();
    let conf = fs::read_to_string(w.dir.join("ssk.d/work.conf")).unwrap();
    assert!(
        conf.contains("Host b.test") && !conf.contains("Host a.test"),
        "{conf}"
    );
    assert!(authorized_keys(&w, "b.test").contains(&blob(&w, "work")));
}

/// Two ssk identities on one host: revoking one must not disturb the other, and the
/// verify probe must not mistake the other identity's key for the one being revoked.
#[test]
fn revoke_leaves_another_identity_on_the_same_host_alone() {
    let w = world();
    cmd(&w)
        .args(["new", "github", "--no-passphrase"])
        .assert()
        .success();
    for id in ["work", "github"] {
        cmd(&w).args(["copy", id, "a.test"]).assert().success();
    }
    let github_conf = fs::read_to_string(w.dir.join("ssk.d/github.conf")).unwrap();

    cmd(&w)
        .args(["revoke", "work", "a.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("revoked and verified"));

    let ak = authorized_keys(&w, "a.test");
    assert!(!ak.contains(&blob(&w, "work")), "{ak}");
    assert!(
        ak.contains(&blob(&w, "github")),
        "github's key is gone:\n{ak}"
    );
    assert_eq!(
        fs::read_to_string(w.dir.join("ssk.d/github.conf")).unwrap(),
        github_conf,
        "github's generated config must be untouched"
    );
    assert!(!w.dir.join("ssk.d/work.conf").exists());
}

#[test]
fn revoke_unreachable_host_keeps_the_record() {
    let w = world();
    cmd(&w).args(["copy", "work", "a.test"]).assert().success();
    let down = unreachable_ssh(&w.root);
    cmd(&w)
        .env("SSK_SSH_BIN", &down)
        .args(["revoke", "work", "a.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("255"));
    assert!(state(&w).contains("deployments"));
    assert!(w.dir.join("ssk.d/work.conf").exists());
}

#[test]
fn revoke_dry_run_makes_no_calls() {
    let w = world();
    cmd(&w)
        .args(["--dry-run", "revoke", "work", "a.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would run"))
        .stdout(predicate::str::contains("exec sh -c"));
    assert!(!w.root.join("args.log").exists());
}
