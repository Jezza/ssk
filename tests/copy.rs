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

const HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOxSJm+vKgPtjF+3LXECms+G30LapzDZVnEL1zVmOdBP";

#[test]
fn copy_to_a_reinstalled_host_points_at_replace_host_key() {
    let w = world();
    let fake = fake_ssh(&w.root);
    let kh = w.root.join("known_hosts");
    let before = format!("[example.test]:2222 {HOST_KEY}\n");
    fs::write(&kh, &before).unwrap();
    copy_cmd(&w, &fake, &w.root)
        .env("FAKE_SSH_KNOWN_HOSTS", &kh)
        .args(["copy", "work", "deploy@example.test:2222"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no longer matches known_hosts"))
        .stderr(predicate::str::contains("--replace-host-key"));
    assert_eq!(fs::read_to_string(&kh).unwrap(), before);
}

#[test]
fn copy_replace_host_key_forgets_the_old_key_and_installs() {
    if which::which("ssh-keygen").is_err() {
        return;
    }
    let w = world();
    let fake = fake_ssh(&w.root);
    let kh = w.root.join("known_hosts");
    fs::write(
        &kh,
        format!("[example.test]:2222 {HOST_KEY}\nother.test {HOST_KEY}\n"),
    )
    .unwrap();
    copy_cmd(&w, &fake, &w.root)
        .env("FAKE_SSH_KNOWN_HOSTS", &kh)
        .args([
            "copy",
            "work",
            "deploy@example.test:2222",
            "--replace-host-key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "removed the old host key for [example.test]:2222",
        ))
        .stdout(predicate::str::contains("installed and verified"));
    assert_eq!(
        fs::read_to_string(&kh).unwrap(),
        format!("other.test {HOST_KEY}\n")
    );
    assert!(w.root.join("known_hosts.old").exists());
}

#[test]
fn copy_replace_host_key_dry_run_mentions_the_step() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args([
            "--dry-run",
            "copy",
            "work",
            "example.test",
            "--replace-host-key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("if the host key has changed"))
        .stdout(predicate::str::contains("ssh-keygen -R"));
    assert!(!w.root.join("args.log").exists());
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
fn copy_rejects_an_unusable_alias_before_any_ssh() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "a.test", "--alias", "bad name"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not a usable Host alias"));
    assert!(!w.root.join("args.log").exists());
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

#[test]
fn new_with_one_copy_target_aliases_it_to_the_identity() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args([
            "new",
            "deploykey",
            "--no-passphrase",
            "--copy",
            "deploy@example.test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh deploykey"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(
        conf.contains("Host deploykey\n    HostName example.test\n    User deploy\n"),
        "{conf}"
    );
    let state = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.toml")).unwrap();
    assert!(state.contains("alias = \"deploykey\""), "{state}");
}

#[test]
fn new_with_several_copy_targets_keeps_the_hosts_as_aliases() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args([
            "new",
            "deploykey",
            "--no-passphrase",
            "--copy",
            "a.test",
            "--copy",
            "b.test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh").not());
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(
        conf.contains("Host a.test\n") && conf.contains("Host b.test\n"),
        "{conf}"
    );
    assert!(!conf.contains("HostName"), "{conf}");
    assert!(!conf.contains("Host deploykey"), "{conf}");
}

#[test]
fn new_copy_alias_flag_overrides_the_default() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args([
            "new",
            "deploykey",
            "--no-passphrase",
            "--copy",
            "deploy@example.test",
            "--alias",
            "prod1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh prod1"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(
        conf.contains("Host prod1\n    HostName example.test\n"),
        "{conf}"
    );
    assert!(!conf.contains("Host deploykey"), "{conf}");
}

#[test]
fn new_alias_needs_copy_and_exactly_one_target() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["new", "deploykey", "--no-passphrase", "--alias", "x"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--copy"));
    copy_cmd(&w, &fake, &w.root)
        .args([
            "new",
            "deploykey",
            "--no-passphrase",
            "--copy",
            "a.test",
            "--copy",
            "b.test",
            "--alias",
            "x",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("exactly one target"));
    copy_cmd(&w, &fake, &w.root)
        .args([
            "new",
            "deploykey",
            "--no-passphrase",
            "--copy",
            "a.test",
            "--alias",
            "bad name",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not a usable Host alias"));
    assert!(
        !Path::new(&w.ssh_dir).join("deploykey").exists(),
        "a bad --alias must be caught before the key is generated"
    );
    assert!(!w.root.join("args.log").exists(), "and before any ssh");
}

#[test]
fn new_copy_falls_back_to_the_host_when_the_identity_name_is_already_an_alias() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "a.test", "--alias", "deploykey"])
        .assert()
        .success();
    copy_cmd(&w, &fake, &w.root)
        .args(["new", "deploykey", "--no-passphrase", "--copy", "b.test"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "already the alias of work: a.test",
        ))
        .stdout(predicate::str::contains("next: ssh b.test"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(conf.contains("Host b.test\n"), "{conf}");
    assert!(!conf.contains("Host deploykey"), "{conf}");
    let state = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.toml")).unwrap();
    assert_eq!(state.matches("alias = \"deploykey\"").count(), 1, "{state}");
}

#[test]
fn copy_hints_ssh_alias_for_one_target_only_when_config_was_written() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "example.test", "--alias", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh dev"));
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "a.test", "b.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh").not());
    copy_cmd(&w, &fake, &w.root)
        .args(["copy", "work", "c.test", "--no-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh").not());
}

#[test]
fn new_copy_keeps_the_host_as_alias_when_it_is_a_host_in_your_config() {
    let w = world();
    let fake = fake_ssh(&w.root);
    let cfg = Path::new(&w.ssh_dir).join("config");
    fs::write(
        &cfg,
        "Host mybox\n    HostName example.test\n    Port 2222\n",
    )
    .unwrap();
    copy_cmd(&w, &fake, &w.root)
        .args(["new", "deploykey", "--no-passphrase", "--copy", "mybox"])
        .assert()
        .success()
        .stdout(predicate::str::contains("'mybox' is a Host in"))
        .stdout(predicate::str::contains("next: ssh mybox"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(conf.contains("Host mybox\n    IdentityFile"), "{conf}");
    assert!(!conf.contains("Host deploykey"), "{conf}");
    let cfg_text = fs::read_to_string(&cfg).unwrap();
    assert!(
        cfg_text.contains("Host mybox\n    HostName example.test\n"),
        "{cfg_text}"
    );
}

#[test]
fn new_copy_falls_back_when_the_identity_name_is_a_host_in_your_config() {
    let w = world();
    let fake = fake_ssh(&w.root);
    fs::write(
        Path::new(&w.ssh_dir).join("config"),
        "Host deploykey\n    HostName elsewhere.test\n",
    )
    .unwrap();
    copy_cmd(&w, &fake, &w.root)
        .args(["new", "deploykey", "--no-passphrase", "--copy", "b.test"])
        .assert()
        .success()
        .stderr(predicate::str::contains("'deploykey' is already a Host in"))
        .stdout(predicate::str::contains("next: ssh b.test"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(conf.contains("Host b.test\n"), "{conf}");
    assert!(!conf.contains("Host deploykey"), "{conf}");
}

#[test]
fn new_copy_ignores_host_blocks_that_apply_to_both_names() {
    let w = world();
    let fake = fake_ssh(&w.root);
    fs::write(
        Path::new(&w.ssh_dir).join("config"),
        "Host *\n    ServerAliveInterval 30\n",
    )
    .unwrap();
    copy_cmd(&w, &fake, &w.root)
        .args([
            "new",
            "deploykey",
            "--no-passphrase",
            "--copy",
            "example.test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh deploykey"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(
        conf.contains("Host deploykey\n    HostName example.test\n"),
        "{conf}"
    );
}

#[test]
fn new_copy_sees_host_blocks_in_included_files() {
    let w = world();
    let fake = fake_ssh(&w.root);
    let dir = Path::new(&w.ssh_dir);
    fs::create_dir_all(dir.join("config.d")).unwrap();
    fs::write(
        dir.join("config.d/lan.conf"),
        "Host mybox\n    HostName example.test\n",
    )
    .unwrap();
    fs::write(dir.join("config"), "Include config.d/*.conf\n").unwrap();
    copy_cmd(&w, &fake, &w.root)
        .args(["new", "deploykey", "--no-passphrase", "--copy", "mybox"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config.d/lan.conf"))
        .stdout(predicate::str::contains("next: ssh mybox"));
    let conf = fs::read_to_string(dir.join("ssk.d/deploykey.conf")).unwrap();
    assert!(conf.contains("Host mybox\n    IdentityFile"), "{conf}");
}

#[test]
fn new_force_to_the_same_endpoint_keeps_the_identity_alias_without_a_warning() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["new", "deploykey", "--no-passphrase", "--copy", "a.test"])
        .assert()
        .success();
    copy_cmd(&w, &fake, &w.root)
        .args([
            "-y",
            "new",
            "deploykey",
            "--force",
            "--no-passphrase",
            "--copy",
            "a.test",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("already the alias").not())
        .stdout(predicate::str::contains("next: ssh deploykey"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert_eq!(
        conf.matches("Host deploykey\n    HostName a.test\n")
            .count(),
        1,
        "{conf}"
    );
    let state = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.toml")).unwrap();
    assert_eq!(
        state.matches("[[identity.deploykey.deployments]]").count(),
        1,
        "{state}"
    );
}

#[test]
fn new_copy_to_a_host_named_like_the_identity_writes_a_plain_block() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .args(["new", "deploykey", "--no-passphrase", "--copy", "deploykey"])
        .assert()
        .success()
        .stderr(predicate::str::contains("alias").not())
        .stdout(predicate::str::contains("next: ssh deploykey"));
    let conf = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.d/deploykey.conf")).unwrap();
    assert!(conf.contains("Host deploykey\n    IdentityFile"), "{conf}");
    assert!(!conf.contains("HostName"), "{conf}");
}

#[test]
fn new_copy_without_ssh_config_records_the_alias_but_writes_no_block_or_hint() {
    let w = world();
    let fake = fake_ssh(&w.root);
    copy_cmd(&w, &fake, &w.root)
        .env("SSK_WRITE_SSH_CONFIG", "false")
        .args(["new", "deploykey", "--no-passphrase", "--copy", "a.test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("next: ssh").not());
    assert!(!Path::new(&w.ssh_dir).join("ssk.d").exists());
    let state = fs::read_to_string(Path::new(&w.ssh_dir).join("ssk.toml")).unwrap();
    assert!(state.contains("alias = \"deploykey\""), "{state}");
}
