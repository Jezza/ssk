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
}

fn world(names: &[&str]) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let dir = root.join("ssh");
    let s = dir.to_str().unwrap().to_string();
    for name in names {
        ssk()
            .args(["--ssh-dir", &s, "new", name, "--no-passphrase"])
            .assert()
            .success();
    }
    World {
        _tmp: tmp,
        root,
        dir,
        s,
    }
}

fn cmd(w: &World) -> assert_cmd::Command {
    let mut c = ssk();
    c.args(["--ssh-dir", &w.s]);
    c
}

fn deploy(w: &World, name: &str, target: &str, extra: &[&str]) {
    let fake = fake_ssh(&w.root);
    cmd(w)
        .env("SSK_SSH_BIN", &fake)
        .env("FAKE_SSH_DIR", &w.root)
        .args(["copy", name, target])
        .args(extra)
        .assert()
        .success();
}

fn conf(w: &World, name: &str) -> String {
    fs::read_to_string(w.dir.join(format!("ssk.d/{name}.conf"))).unwrap_or_default()
}

fn state(w: &World) -> String {
    fs::read_to_string(w.dir.join("ssk.toml")).unwrap_or_default()
}

fn ssh_calls(w: &World) -> usize {
    fs::read_to_string(w.root.join("args.log"))
        .unwrap_or_default()
        .lines()
        .count()
}

#[test]
fn alias_by_host_rewrites_state_and_conf_without_ssh() {
    let w = world(&["work"]);
    deploy(&w, "work", "jezza@dev.test", &[]);
    let calls = ssh_calls(&w);
    cmd(&w)
        .args(["alias", "dev", "dev.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("work: jezza@dev.test"))
        .stdout(predicate::str::contains("dev"));
    assert_eq!(ssh_calls(&w), calls, "alias must not run ssh");
    let c = conf(&w, "work");
    assert!(c.contains("Host dev\n    HostName dev.test\n"), "{c}");
    assert!(state(&w).contains("alias = \"dev\""), "{}", state(&w));
}

#[test]
fn alias_by_existing_alias_and_by_endpoint() {
    let w = world(&["work"]);
    deploy(&w, "work", "jezza@dev.test:2222", &["--alias", "dev"]);
    cmd(&w).args(["alias", "box", "dev"]).assert().success();
    assert!(
        conf(&w, "work").contains("Host box\n"),
        "{}",
        conf(&w, "work")
    );
    cmd(&w)
        .args(["alias", "box2", "jezza@dev.test:2222"])
        .assert()
        .success();
    let c = conf(&w, "work");
    assert!(c.contains("Host box2\n"), "{c}");
    assert!(!c.contains("Host box\n"), "{c}");
}

#[test]
fn reset_puts_the_host_back() {
    let w = world(&["work"]);
    deploy(&w, "work", "dev.test", &["--alias", "dev"]);
    cmd(&w).args(["alias", "--reset", "dev"]).assert().success();
    let c = conf(&w, "work");
    assert!(c.contains("Host dev.test\n"), "{c}");
    assert!(!c.contains("HostName"), "{c}");
}

#[test]
fn ambiguous_target_lists_matches_and_identity_narrows_it() {
    let w = world(&["work", "home"]);
    deploy(&w, "work", "dev.test", &[]);
    deploy(&w, "home", "dev.test", &[]);
    cmd(&w)
        .args(["alias", "dev", "dev.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("matches 2 deployments"))
        .stderr(predicate::str::contains("work: dev.test"))
        .stderr(predicate::str::contains("home: dev.test"))
        .stderr(predicate::str::contains("-i"));
    cmd(&w)
        .args(["alias", "dev", "dev.test", "-i", "work"])
        .assert()
        .success();
    assert!(conf(&w, "work").contains("Host dev\n"));
    assert!(conf(&w, "home").contains("Host dev.test\n"));
}

#[test]
fn refuses_an_alias_already_taken_and_unknown_targets() {
    let w = world(&["work"]);
    deploy(&w, "work", "a.test", &["--alias", "a"]);
    deploy(&w, "work", "b.test", &[]);
    cmd(&w)
        .args(["alias", "a", "b.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "already the alias of work: a.test",
        ));
    cmd(&w)
        .args(["alias", "x", "nope.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "no deployment matches 'nope.test'",
        ));
    cmd(&w)
        .args(["alias", "bad name", "b.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not a usable Host alias"));
}

#[test]
fn same_alias_is_a_no_op_and_dry_run_changes_nothing() {
    let w = world(&["work"]);
    deploy(&w, "work", "a.test", &["--alias", "a"]);
    cmd(&w)
        .args(["alias", "a", "a"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already"));
    let before = (state(&w), conf(&w, "work"));
    cmd(&w)
        .args(["--dry-run", "alias", "b", "a"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dry run"));
    assert_eq!((state(&w), conf(&w, "work")), before);
}

#[test]
fn needs_both_names_unless_resetting() {
    ssk().args(["alias", "dev"]).assert().code(2);
    ssk()
        .args(["alias", "--reset", "dev", "extra"])
        .assert()
        .code(2);
}
