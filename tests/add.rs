mod common;

use std::fs;
use std::path::PathBuf;

use common::{fake_ssh_add, ssk};
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
    for name in ["work", "github"] {
        ssk()
            .args(["--ssh-dir", &s, "new", name, "--no-passphrase"])
            .assert()
            .success();
    }
    let fake = fake_ssh_add(&root);
    World {
        _tmp: tmp,
        root,
        dir,
        s,
        fake,
    }
}

fn agent(w: &World) -> assert_cmd::Command {
    let mut c = ssk();
    c.env("SSH_AUTH_SOCK", "/nonexistent/agent.sock")
        .env("SSK_SSH_ADD_BIN", &w.fake)
        .env("FAKE_AGENT_DIR", &w.root)
        .args(["--ssh-dir", &w.s]);
    c
}

fn log(w: &World) -> Vec<String> {
    fs::read_to_string(w.root.join("ssh-add.log"))
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

fn fingerprint(w: &World, name: &str) -> String {
    let out = ssk()
        .args(["--ssh-dir", &w.s, "show", name, "--fingerprint"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn add_without_an_agent_fails_clearly() {
    let w = world();
    ssk()
        .args(["--ssh-dir", &w.s, "add"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no ssh-agent"));
}

#[test]
fn add_all_loads_every_unloaded_identity() {
    let w = world();
    agent(&w)
        .arg("add")
        .assert()
        .success()
        .stdout(predicate::str::contains("github: added"))
        .stdout(predicate::str::contains("work: added"));
    assert_eq!(
        log(&w),
        vec![
            "-l".to_string(),
            w.dir.join("github").display().to_string(),
            w.dir.join("work").display().to_string(),
        ]
    );
}

#[test]
fn add_skips_keys_already_in_the_agent() {
    let w = world();
    let fp = fingerprint(&w, "work");
    fs::write(
        w.root.join("loaded"),
        format!("256 {fp} work@box (ED25519)\n"),
    )
    .unwrap();
    agent(&w)
        .args(["add", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("work: already in agent"));
    assert_eq!(log(&w), vec!["-l".to_string()]);
}

#[test]
fn add_unknown_name_fails_before_touching_the_agent() {
    let w = world();
    agent(&w)
        .args(["add", "wrk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("did you mean 'work'"));
    assert!(!w.root.join("ssh-add.log").exists());
}

#[test]
fn add_reports_failures_and_continues() {
    let w = world();
    agent(&w)
        .env("FAKE_SSH_ADD_FAIL", "1")
        .args(["add", "work", "github"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("work:"))
        .stderr(predicate::str::contains("github:"));
    assert_eq!(log(&w).len(), 3, "{:?}", log(&w));
}

#[test]
fn add_dry_run_prints_commands_only() {
    let w = world();
    agent(&w)
        .args(["--dry-run", "add"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would run: ssh-add"));
    assert!(!w.root.join("ssh-add.log").exists());
}

#[test]
fn new_honours_add_to_agent_and_no_add() {
    let w = world();
    let cfg = w.root.join("config.toml");
    fs::write(&cfg, "add_to_agent = true\n").unwrap();
    agent(&w)
        .env("SSK_CONFIG", &cfg)
        .args(["new", "k", "--no-passphrase"])
        .assert()
        .success();
    assert!(log(&w).iter().any(|l| l.ends_with("/k")), "{:?}", log(&w));
    agent(&w)
        .env("SSK_CONFIG", &cfg)
        .args(["new", "k2", "--no-passphrase", "--no-add"])
        .assert()
        .success();
    assert!(!log(&w).iter().any(|l| l.ends_with("/k2")), "{:?}", log(&w));
}
