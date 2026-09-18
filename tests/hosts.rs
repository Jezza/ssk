mod common;

use std::path::PathBuf;

use common::{fake_ssh, ssk};
use predicates::prelude::*;

fn world() -> (tempfile::TempDir, PathBuf, String, PathBuf) {
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
    let fake = fake_ssh(&root);
    (tmp, root, s, fake)
}

#[test]
fn hosts_is_empty_until_something_is_copied() {
    let (_tmp, _root, s, _fake) = world();
    ssk()
        .args(["--ssh-dir", &s, "hosts"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no deployments recorded"));
    let out = ssk()
        .args(["--ssh-dir", &s, "hosts", "--json"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "[]");
}

#[test]
fn hosts_shows_the_matrix_and_json() {
    let (_tmp, root, s, fake) = world();
    let copy = |name: &str, targets: &[&str]| {
        let mut c = ssk();
        c.env("SSK_SSH_BIN", &fake)
            .env("FAKE_SSH_DIR", &root)
            .args(["--ssh-dir", &s, "copy", name]);
        c.args(targets).assert().success();
    };
    copy("work", &["deploy@a.test:2222", "b.test"]);
    copy("github", &["b.test"]);
    let out = ssk().args(["--ssh-dir", &s, "hosts"]).assert().success();
    let text = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let a = text
        .lines()
        .find(|l| l.contains("deploy@a.test:2222"))
        .unwrap();
    let b = text.lines().find(|l| l.contains("b.test")).unwrap();
    assert_eq!(a.matches('✓').count(), 1, "{text}");
    assert_eq!(b.matches('✓').count(), 2, "{text}");
    assert!(text.lines().next().unwrap().contains("github"), "{text}");

    let out = ssk()
        .args(["--ssh-dir", &s, "hosts", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let b = arr.iter().find(|r| r["host"] == "b.test").unwrap();
    assert_eq!(b["identities"].as_array().unwrap().len(), 2);
    assert_eq!(b["port"], 22);
}
