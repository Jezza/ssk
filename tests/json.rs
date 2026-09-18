mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use common::{fake_ssh, ssk};
use serde_json::Value;

fn world() -> (tempfile::TempDir, PathBuf, String) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("ssh");
    let s = dir.to_str().unwrap().to_string();
    ssk()
        .args(["--ssh-dir", &s, "new", "work", "--no-passphrase"])
        .assert()
        .success();
    (tmp, dir, s)
}

fn json_of(cmd: &mut assert_cmd::Command) -> (Value, i32) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}):\n{stdout}"));
    (v, out.status.code().unwrap())
}

#[test]
fn list_json_is_an_array_with_documented_keys() {
    let (_tmp, dir, s) = world();
    fs::write(
        dir.join("old"),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::write(dir.join("lost.pub"), "ssh-ed25519 AAAA lost\n").unwrap();
    let (v, code) = json_of(ssk().args(["--ssh-dir", &s, "list", "--json"]));
    assert_eq!(code, 0);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    let by = |name: &str| arr.iter().find(|e| e["name"] == name).unwrap().clone();
    let work = by("work");
    assert_eq!(work["status"], "ok");
    assert_eq!(work["type"], "ed25519");
    assert_eq!(work["bits"], Value::Null);
    assert_eq!(work["in_agent"], Value::Null);
    assert_eq!(work["hosts"], 0);
    assert_eq!(work["managed"], true);
    assert_eq!(work["encrypted"], false);
    assert!(work["public_path"].as_str().unwrap().ends_with("work.pub"));
    assert_eq!(arr[0]["name"], "work", "managed first");
    assert_eq!(by("old")["status"], "unreadable");
    assert!(by("old")["error"].as_str().unwrap().contains("legacy"));
    assert_eq!(by("lost")["status"], "orphan-pub");
}

#[test]
fn show_json_has_modes_created_and_public_key() {
    let (_tmp, _dir, s) = world();
    let (v, code) = json_of(ssk().args(["--ssh-dir", &s, "show", "work", "--json"]));
    assert_eq!(code, 0);
    assert_eq!(v["status"], "ok");
    assert_eq!(v["name"], "work");
    assert_eq!(v["private_mode"], "0600");
    assert_eq!(v["public_mode"], "0644");
    assert!(v["created"].as_str().unwrap().ends_with('Z'));
    assert_eq!(v["deployments"].as_array().unwrap().len(), 0);
    assert_eq!(v["ssh_config"], Value::Null);
    assert!(
        v["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
}

#[test]
fn show_json_lists_deployments_after_copy() {
    let (tmp, dir, s) = world();
    let fake = fake_ssh(tmp.path());
    ssk()
        .env("SSK_SSH_BIN", &fake)
        .env("FAKE_SSH_DIR", tmp.path())
        .args(["--ssh-dir", &s, "copy", "work", "deploy@a.test:2222"])
        .assert()
        .success();
    let (v, _) = json_of(ssk().args(["--ssh-dir", &s, "show", "work", "--json"]));
    let d = &v["deployments"][0];
    assert_eq!(d["host"], "a.test");
    assert_eq!(d["user"], "deploy");
    assert_eq!(d["port"], 2222);
    assert_eq!(d["alias"], "a.test");
    assert_eq!(
        v["ssh_config"].as_str().unwrap(),
        dir.join("ssk.d/work.conf").to_str().unwrap()
    );
    assert_eq!(v["hosts"], 1);
}

#[test]
fn doctor_json_reports_and_fixes() {
    let (_tmp, dir, s) = world();
    let (v, code) = json_of(ssk().args(["--ssh-dir", &s, "doctor", "--json"]));
    assert_eq!(code, 0);
    assert_eq!(v, serde_json::json!({"findings": [], "applied": 0}));

    fs::set_permissions(dir.join("work.pub"), fs::Permissions::from_mode(0o666)).unwrap();
    let (v, code) = json_of(ssk().args(["--ssh-dir", &s, "doctor", "--json"]));
    assert_eq!(code, 1);
    assert_eq!(v["findings"][0]["id"], "pub-writable");
    assert_eq!(v["findings"][0]["severity"], "warn");
    assert_eq!(v["findings"][0]["fixable"], true);
    assert_eq!(v["applied"], 0);

    let (v, code) = json_of(ssk().args(["--ssh-dir", &s, "doctor", "--fix", "--json"]));
    assert_eq!(code, 0);
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    assert_eq!(v["applied"], 1);
    assert_eq!(common::mode(&dir.join("work.pub")), 0o644);
}

#[test]
fn quiet_does_not_swallow_json() {
    let (_tmp, _dir, s) = world();
    let (v, _) = json_of(ssk().args(["--ssh-dir", &s, "-q", "list", "--json"]));
    assert_eq!(v.as_array().unwrap().len(), 1);
}
