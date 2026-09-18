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

/// `SHA256:...` of `work`, as `ssh-add -l` would print it.
fn fingerprint(w: &World) -> String {
    let out = cmd(w)
        .args(["show", "work", "--fingerprint"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// The key blob (second field) of `work.pub`.
fn blob(w: &World) -> String {
    let line = fs::read_to_string(w.dir.join("work.pub")).unwrap();
    line.split_whitespace().nth(1).unwrap().to_string()
}

/// `cmd` talking to the fake ssh-add in `w.root`.
fn agent_cmd(w: &World) -> assert_cmd::Command {
    let fake = fake_ssh_add(&w.root);
    let mut c = cmd(w);
    c.env("SSH_AUTH_SOCK", "/nonexistent/agent.sock")
        .env("SSK_SSH_ADD_BIN", &fake)
        .env("FAKE_AGENT_DIR", &w.root);
    c
}

fn ssh_add_log(w: &World) -> String {
    fs::read_to_string(w.root.join("ssh-add.log")).unwrap_or_default()
}

#[test]
fn rm_drops_the_key_from_the_agent_when_loaded() {
    let w = world();
    fs::write(
        w.root.join("loaded"),
        format!("256 {} work@box (ED25519)\n", fingerprint(&w)),
    )
    .unwrap();
    agent_cmd(&w).args(["-y", "rm", "work"]).assert().success();
    let log = ssh_add_log(&w);
    assert!(
        log.contains(&format!("-d {}", w.dir.join("work").display())),
        "{log}"
    );
}

/// gcr-ssh-agent (GNOME) lists every `~/.ssh/*.pub` as loaded, refuses `ssh-add -d` for the
/// ones it never actually holds, and stops listing them once the .pub is gone. Nothing was
/// in the agent, so nothing is worth a warning, and ssh-add's complaint stays out of sight.
#[test]
fn rm_stays_quiet_when_the_agent_only_listed_the_key_from_its_pub() {
    let w = world();
    fs::write(
        w.root.join("advertised"),
        format!(
            "{} {} 256 {} work@box (ED25519)\n",
            w.dir.join("work.pub").display(),
            blob(&w),
            fingerprint(&w)
        ),
    )
    .unwrap();
    agent_cmd(&w)
        .env("FAKE_SSH_ADD_REFUSE", "1")
        .args(["-y", "rm", "work"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains("removed identity work"));
    assert!(ssh_add_log(&w).contains("-d "), "{}", ssh_add_log(&w));
    assert!(!w.dir.join("work").exists());
}

/// A real agent that refuses the delete still holds the key after the files are gone: that
/// is the one case worth a warning, and the warning line carries ssh-add's reason.
#[test]
fn rm_warns_when_the_agent_refuses_to_drop_a_key_it_still_holds() {
    let w = world();
    fs::write(
        w.root.join("loaded"),
        format!("256 {} work@box (ED25519)\n", fingerprint(&w)),
    )
    .unwrap();
    agent_cmd(&w)
        .env("FAKE_SSH_ADD_REFUSE", "1")
        .args(["-y", "rm", "work"])
        .assert()
        .success()
        .stderr(predicate::function(|s: &str| {
            s.lines().any(|l| {
                l.contains("could not remove 'work' from ssh-agent")
                    && l.contains("agent refused operation")
            })
        }))
        .stdout(predicate::str::contains("removed identity work"));
    assert!(!w.dir.join("work").exists());
}

#[test]
fn rename_moves_files_state_and_generated_config() {
    let w = world();
    deploy(&w, "work", "a.test");
    cmd(&w)
        .args(["rename", "work", "job"])
        .assert()
        .success()
        .stdout(predicate::str::contains("renamed identity work -> job"));
    assert!(w.dir.join("job").exists() && w.dir.join("job.pub").exists());
    assert!(!w.dir.join("work").exists() && !w.dir.join("work.pub").exists());
    assert!(!w.dir.join("ssk.d/work.conf").exists());
    let conf = fs::read_to_string(w.dir.join("ssk.d/job.conf")).unwrap();
    assert!(
        conf.contains("/job\n") && !conf.contains("/work\n"),
        "{conf}"
    );
    let st = state(&w);
    assert!(
        st.contains("[identity.job]") && !st.contains("[identity.work]"),
        "{st}"
    );
    cmd(&w)
        .args(["show", "job"])
        .assert()
        .success()
        .stdout(predicate::str::contains("a.test"));
}

#[test]
fn rename_refuses_to_clobber_and_needs_a_source() {
    let w = world();
    cmd(&w)
        .args(["new", "github", "--no-passphrase"])
        .assert()
        .success();
    cmd(&w)
        .args(["rename", "work", "github"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    cmd(&w)
        .args(["rename", "wrk", "x"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("did you mean 'work'"));
    cmd(&w)
        .args(["rename", "work", "config"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("reserved"));
    assert!(w.dir.join("work").exists() && w.dir.join("github").exists());
}

/// The files of NEW can be gone while its ssk.toml entry survives; renaming onto that
/// entry would replace it, losing the deployments it still records.
#[test]
fn rename_refuses_when_the_new_name_still_has_a_state_entry() {
    let w = world();
    cmd(&w)
        .args(["new", "job", "--no-passphrase"])
        .assert()
        .success();
    fs::remove_file(w.dir.join("job")).unwrap();
    fs::remove_file(w.dir.join("job.pub")).unwrap();
    assert!(state(&w).contains("[identity.job]"));

    cmd(&w)
        .args(["rename", "work", "job"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("still has an entry in"))
        .stderr(predicate::str::contains("ssk rm job"));
    assert!(w.dir.join("work").exists() && w.dir.join("work.pub").exists());
    assert!(!w.dir.join("job").exists());
    assert!(state(&w).contains("[identity.work]"), "{}", state(&w));
}

#[test]
fn rename_works_on_a_legacy_pem_key_without_a_pub() {
    let w = world();
    fs::write(
        w.dir.join("old"),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    cmd(&w)
        .args(["rename", "old", "ancient"])
        .assert()
        .success();
    assert!(w.dir.join("ancient").exists() && !w.dir.join("old").exists());
}

#[test]
fn rename_warns_about_the_users_own_config() {
    let w = world();
    fs::write(
        w.dir.join("config"),
        format!(
            "Host a\n    IdentityFile {d}/work\nHost b\n    IdentityFile {d}/work2\n",
            d = w.dir.display()
        ),
    )
    .unwrap();
    cmd(&w)
        .args(["--dry-run", "rename", "work", "job"])
        .assert()
        .success()
        .stderr(predicate::str::contains("still mentions 'work'"));
    cmd(&w)
        .args(["rename", "work", "job"])
        .assert()
        .success()
        .stderr(predicate::str::contains("still mentions 'work'"))
        .stderr(predicate::str::contains("2:"))
        .stderr(predicate::str::contains("work2").not());
    assert!(
        fs::read_to_string(w.dir.join("config"))
            .unwrap()
            .contains("/work\n"),
        "user config must not be edited"
    );
}

#[test]
fn rename_dry_run_changes_nothing() {
    let w = world();
    cmd(&w)
        .args(["--dry-run", "rename", "work", "job"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dry run: nothing renamed"));
    assert!(w.dir.join("work").exists() && !w.dir.join("job").exists());
}
