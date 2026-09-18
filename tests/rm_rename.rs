mod common;

use std::fs;
use std::path::PathBuf;

use common::{fake_ssh, fake_ssh_add, ssk};
use predicates::prelude::*;

struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    dir: PathBuf,
    s: String,
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

fn deploy(w: &World, name: &str, target: &str) {
    let fake = fake_ssh(&w.root);
    cmd(w)
        .env("SSK_SSH_BIN", &fake)
        .env("FAKE_SSH_DIR", &w.root)
        .args(["copy", name, target])
        .assert()
        .success();
}

fn state(w: &World) -> String {
    fs::read_to_string(w.dir.join("ssk.toml")).unwrap_or_default()
}

#[test]
fn rm_removes_files_conf_and_state_and_points_at_revoke() {
    let w = world();
    deploy(&w, "work", "deploy@a.test");
    cmd(&w)
        .args(["-y", "rm", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("recorded on 1 host"))
        .stdout(predicate::str::contains("ssk revoke work --all"))
        .stdout(predicate::str::contains("removed identity work"));
    assert!(!w.dir.join("work").exists());
    assert!(!w.dir.join("work.pub").exists());
    assert!(!w.dir.join("ssk.d/work.conf").exists());
    assert!(!state(&w).contains("[identity.work]"), "{}", state(&w));
}

#[test]
fn rm_force_skips_confirmation_and_unknown_names_suggest() {
    let w = world();
    cmd(&w).args(["rm", "work", "-f"]).assert().success();
    cmd(&w)
        .args(["rm", "work", "-f"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no identity named 'work'"));
    cmd(&w)
        .args(["new", "github", "--no-passphrase"])
        .assert()
        .success();
    cmd(&w)
        .args(["rm", "githb", "-f"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("did you mean 'github'"));
}

#[test]
fn rm_without_yes_and_no_tty_refuses_and_keeps_everything() {
    let w = world();
    cmd(&w)
        .args(["rm", "work"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no terminal"));
    assert!(w.dir.join("work").exists() && w.dir.join("work.pub").exists());
}

#[test]
fn rm_dry_run_lists_but_keeps() {
    let w = world();
    cmd(&w)
        .args(["--dry-run", "rm", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            w.dir.join("work.pub").to_str().unwrap(),
        ))
        .stdout(predicate::str::contains("dry run: nothing removed"));
    assert!(w.dir.join("work").exists());
    assert!(state(&w).contains("[identity.work]"));
}

#[test]
fn rm_cleans_a_dangling_state_entry() {
    let w = world();
    fs::remove_file(w.dir.join("work")).unwrap();
    fs::remove_file(w.dir.join("work.pub")).unwrap();
    assert!(state(&w).contains("[identity.work]"));
    cmd(&w)
        .args(["-y", "rm", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entry in"));
    assert!(!state(&w).contains("[identity.work]"));
}

#[test]
fn rm_drops_the_key_from_the_agent_when_loaded() {
    let w = world();
    let fake = fake_ssh_add(&w.root);
    let out = cmd(&w)
        .args(["show", "work", "--fingerprint"])
        .output()
        .unwrap();
    let fp = String::from_utf8(out.stdout).unwrap().trim().to_string();
    fs::write(
        w.root.join("loaded"),
        format!("256 {fp} work@box (ED25519)\n"),
    )
    .unwrap();
    cmd(&w)
        .env("SSH_AUTH_SOCK", "/nonexistent/agent.sock")
        .env("SSK_SSH_ADD_BIN", &fake)
        .env("FAKE_AGENT_DIR", &w.root)
        .args(["-y", "rm", "work"])
        .assert()
        .success();
    let log = fs::read_to_string(w.root.join("ssh-add.log")).unwrap();
    assert!(
        log.contains(&format!("-d {}", w.dir.join("work").display())),
        "{log}"
    );
}
