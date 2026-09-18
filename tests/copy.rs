mod common;

use std::fs;
use std::path::Path;

use common::{fake_ssh, ssk, unreachable_ssh};
use predicates::prelude::*;

struct World {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    ssh_dir: String,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let ssh_dir = root.join("ssh").to_str().unwrap().to_string();
    ssk()
        .args(["--ssh-dir", &ssh_dir, "new", "work", "--no-passphrase"])
        .assert()
        .success();
    World {
        _tmp: tmp,
        root,
        ssh_dir,
    }
}

fn copy_cmd(w: &World, fake: &Path, fake_dir: &Path) -> assert_cmd::Command {
    let mut c = ssk();
    c.env("SSK_SSH_BIN", fake)
        .env("FAKE_SSH_DIR", fake_dir)
        .args(["--ssh-dir", &w.ssh_dir]);
    c
}

#[test]
fn copy_installs_records_and_writes_config() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "deploy@example.test:2222"])
        .assert()
        .success()
        .stdout(predicate::str::contains("installed and verified"))
        .stdout(predicate::str::contains("ssh config written"));

    let log = fs::read_to_string(w.root.join("args.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 3, "{log}");
    assert!(
        lines[0].contains(&format!("-i {}/work", w.ssh_dir)),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains("-p 2222 -l deploy"), "{}", lines[0]);
    assert!(lines[0].ends_with("-- example.test exit"), "{}", lines[0]);
    assert!(lines[1].contains("exec sh -c '"), "{}", lines[1]);
    assert!(!lines[1].contains("-i "), "{}", lines[1]);

    let pub_line = fs::read_to_string(Path::new(&w.ssh_dir).join("work.pub")).unwrap();
    assert_eq!(
        fs::read_to_string(w.root.join("stdin.log")).unwrap(),
        pub_line
    );

    let state = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.toml")).unwrap();
    for needle in [
        "host = \"example.test\"",
        "port = 2222",
        "user = \"deploy\"",
        "alias = \"example.test\"",
    ] {
        assert!(state.contains(needle), "{needle} missing in:\n{state}");
    }
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/work.conf")).unwrap();
    for needle in [
        "Host example.test",
        "User deploy",
        "Port 2222",
        "IdentityFile",
        "IdentitiesOnly yes",
    ] {
        assert!(conf.contains(needle), "{needle} missing in:\n{conf}");
    }
    let cfg = fs::read_to_string(Path::new(&w.ssh_dir).join("config")).unwrap();
    assert!(cfg.lines().next().unwrap().starts_with("Include "), "{cfg}");
    assert!(cfg.contains("ssk.d/*.conf"), "{cfg}");

    // Second run: probe says installed; exactly one more ssh call.
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "deploy@example.test:2222"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already installed"));
    assert_eq!(
        fs::read_to_string(w.root.join("args.log"))
            .unwrap()
            .lines()
            .count(),
        4
    );
}

#[test]
fn copy_dry_run_prints_commands_and_runs_nothing() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["--dry-run", "copy", "work", "example.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would run"))
        .stdout(predicate::str::contains("IdentitiesOnly=yes"));
    assert!(!w.root.join("args.log").exists());
    assert!(!Path::new(&w.ssh_dir).join("ssk.d").exists());
}

#[test]
fn copy_unreachable_host_exits_one_and_records_nothing() {
    let w = world();
    let down = unreachable_ssh(&w.root);
    copy_cmd(&w, &down, &w.root)
        .args(["copy", "work", "example.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("could not connect"))
        .stderr(predicate::str::contains("No route to host"));
    assert!(
        !fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.toml"))
            .unwrap()
            .contains("deployments")
    );
}

#[test]
fn copy_alias_needs_exactly_one_target() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "a.test", "b.test", "--alias", "x"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("exactly one target"));
}

#[test]
fn copy_unknown_identity_fails_before_any_ssh() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "wrk", "example.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no identity named 'wrk'"))
        .stderr(predicate::str::contains("did you mean 'work'"));
    assert!(!w.root.join("args.log").exists());
}

#[test]
fn copy_no_config_leaves_ssh_config_alone() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "example.test", "--no-config"])
        .assert()
        .success();
    assert!(!Path::new(&w.ssh_dir).join("ssk.d").exists());
    assert!(!Path::new(&w.ssh_dir).join("config").exists());
}

#[test]
fn new_with_copy_creates_then_installs() {
    let w = world();
    let fake_dir = w.root.join("fake2");
    fs::create_dir(&fake_dir).unwrap();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &fake_dir)
        .args([
            "new",
            "deploykey",
            "--no-passphrase",
            "--copy",
            "deploy@example.test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("created identity deploykey"))
        .stdout(predicate::str::contains("installed and verified"));
    assert!(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf").exists());
}
