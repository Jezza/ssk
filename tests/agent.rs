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
fn load_without_an_agent_fails_clearly() {
    let w = world();
    ssk()
        .args(["--ssh-dir", &w.s, "agent", "load"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no ssh-agent"));
}

#[test]
fn load_all_loads_every_unloaded_identity() {
    let w = world();
    agent(&w)
        .args(["agent", "load"])
        .assert()
        .success()
        .stdout(predicate::str::contains("github: loaded"))
        .stdout(predicate::str::contains("work: loaded"));
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
fn load_skips_keys_already_in_the_agent() {
    let w = world();
    let fp = fingerprint(&w, "work");
    fs::write(
        w.root.join("loaded"),
        format!("256 {fp} work@box (ED25519)\n"),
    )
    .unwrap();
    agent(&w)
        .args(["agent", "load", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("work: already in agent"));
    assert_eq!(log(&w), vec!["-l".to_string()]);
}

#[test]
fn load_unknown_name_fails_before_touching_the_agent() {
    let w = world();
    agent(&w)
        .args(["agent", "load", "wrk"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("did you mean 'work'"));
    assert!(!w.root.join("ssh-add.log").exists());
}

#[test]
fn load_reports_failures_and_continues() {
    let w = world();
    agent(&w)
        .env("FAKE_SSH_ADD_FAIL", "1")
        .args(["agent", "load", "work", "github"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("work:"))
        .stderr(predicate::str::contains("github:"));
    assert_eq!(log(&w).len(), 3, "{:?}", log(&w));
}

#[test]
fn load_dry_run_prints_commands_only() {
    let w = world();
    agent(&w)
        .args(["--dry-run", "agent", "load"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would run: ssh-add"));
    assert!(!w.root.join("ssh-add.log").exists());
}

#[test]
fn new_honours_add_to_agent_and_no_load() {
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
        .args(["new", "k2", "--no-passphrase", "--no-load"])
        .assert()
        .success();
    assert!(!log(&w).iter().any(|l| l.ends_with("/k2")), "{:?}", log(&w));
}

/// Make the fake agent report `names` as loaded.
fn load(w: &World, names: &[&str]) {
    let lines: String = names
        .iter()
        .map(|n| format!("256 {} {n}@box (ED25519)\n", fingerprint(w, n)))
        .collect();
    fs::write(w.root.join("loaded"), lines).unwrap();
}

#[test]
fn unload_all_removes_only_loaded_identities() {
    let w = world();
    load(&w, &["work"]);
    agent(&w)
        .args(["agent", "unload"])
        .assert()
        .success()
        .stdout(predicate::str::contains("work: unloaded"))
        .stdout(predicate::str::contains("github").not());
    assert_eq!(
        log(&w),
        vec![
            "-l".to_string(),
            format!("-d {}", w.dir.join("work").display())
        ]
    );
}

#[test]
fn unload_named_reports_keys_not_loaded() {
    let w = world();
    agent(&w)
        .args(["agent", "unload", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("work: not in agent"));
    assert_eq!(log(&w), vec!["-l".to_string()]);
}

#[test]
fn unload_failure_is_reported() {
    let w = world();
    load(&w, &["work"]);
    agent(&w)
        .env("FAKE_SSH_ADD_REFUSE", "1")
        .args(["agent", "unload", "work"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("agent refused operation"));
}

#[test]
fn unload_dry_run_prints_commands_only() {
    let w = world();
    load(&w, &["work", "github"]);
    agent(&w)
        .args(["--dry-run", "agent", "unload"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would run: ssh-add -d"));
    assert_eq!(log(&w), vec!["-l".to_string()]);
}

#[test]
fn list_names_identities_and_shows_foreign_keys() {
    let w = world();
    load(&w, &["work"]);
    let mut loaded = fs::read_to_string(w.root.join("loaded")).unwrap();
    loaded.push_str("3072 SHA256:someoneelse laptop key (RSA)\n");
    fs::write(w.root.join("loaded"), loaded).unwrap();
    agent(&w)
        .args(["agent", "list"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"(?m)^\s*work\s+SHA256:\S+\s+work@box\s*$").unwrap())
        .stdout(
            predicate::str::is_match(r"(?m)^\s*-\s+SHA256:someoneelse\s+laptop key\s*$").unwrap(),
        )
        .stdout(predicate::str::contains("github").not());
}

#[test]
fn list_with_an_empty_agent_or_none() {
    let w = world();
    agent(&w)
        .args(["agent", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("holds no keys"));
    ssk()
        .args(["--ssh-dir", &w.s, "agent", "list"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no ssh-agent"));
}

#[test]
fn add_is_gone() {
    ssk().arg("add").assert().code(2);
}
