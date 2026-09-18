mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::{fake_ssh, mode, ssk};
use predicates::prelude::*;

pub struct World {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub ssh_dir: String,
    pub config: PathBuf,
}

pub fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let ssh_dir = root.join("ssh").to_str().unwrap().to_string();
    let config = root.join("cfg").join("config.toml");
    World {
        _tmp: tmp,
        root,
        ssh_dir,
        config,
    }
}

pub fn write_config(w: &World, text: &str) {
    fs::create_dir_all(w.config.parent().unwrap()).unwrap();
    fs::write(&w.config, text).unwrap();
}

pub fn cmd(w: &World) -> assert_cmd::Command {
    let mut c = ssk();
    c.env("SSK_CONFIG", &w.config)
        .args(["--ssh-dir", &w.ssh_dir]);
    c
}

#[test]
fn file_sets_default_type_and_rsa_bits() {
    let w = world();
    write_config(&w, "default_type = \"rsa\"\nrsa_bits = 2048\n");
    cmd(&w)
        .args(["new", "k", "--no-passphrase"])
        .assert()
        .success();
    cmd(&w)
        .args(["show", "k"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rsa 2048"));
}

#[test]
fn env_beats_file_and_flag_beats_env() {
    let w = world();
    write_config(&w, "default_type = \"rsa\"\n");
    cmd(&w)
        .env("SSK_DEFAULT_TYPE", "ecdsa")
        .args(["new", "a", "--no-passphrase"])
        .assert()
        .success();
    cmd(&w)
        .args(["show", "a"])
        .assert()
        .stdout(predicate::str::contains("ecdsa 256"));
    cmd(&w)
        .env("SSK_DEFAULT_TYPE", "ecdsa")
        .args(["new", "b", "--no-passphrase", "-t", "ed25519"])
        .assert()
        .success();
    cmd(&w)
        .args(["show", "b"])
        .assert()
        .stdout(predicate::str::contains("type         ed25519"));
}

#[test]
fn unknown_key_and_bad_values_are_errors_naming_the_source() {
    let w = world();
    write_config(&w, "ssh-dir = \"/x\"\n");
    cmd(&w)
        .arg("list")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("config.toml"))
        .stderr(predicate::str::contains("ssh-dir"));
    write_config(&w, "rsa_bits = 1024\n");
    cmd(&w)
        .arg("list")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("rsa_bits"));
    write_config(&w, "");
    cmd(&w)
        .env("SSK_RSA_BITS", "17")
        .arg("list")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("SSK_RSA_BITS"));
}

#[test]
fn comment_template_comes_from_the_file() {
    let w = world();
    write_config(&w, "comment = \"{user}-{identity}\"\n");
    cmd(&w)
        .args(["new", "k", "--no-passphrase"])
        .assert()
        .success();
    let pub_line = fs::read_to_string(Path::new(&w.ssh_dir).join("k.pub")).unwrap();
    assert!(pub_line.trim().ends_with("-k"), "{pub_line}");
}

#[test]
fn write_ssh_config_false_is_overridden_by_the_flag() {
    let w = world();
    write_config(&w, "write_ssh_config = false\n");
    cmd(&w)
        .args(["new", "k", "--no-passphrase"])
        .assert()
        .success();
    let fake = fake_ssh(&w.root);
    cmd(&w)
        .env("SSK_SSH_BIN", &fake)
        .env("FAKE_SSH_DIR", &w.root)
        .args(["copy", "k", "a.test"])
        .assert()
        .success();
    assert!(!Path::new(&w.ssh_dir).join("ssk.d").exists());
    cmd(&w)
        .env("SSK_SSH_BIN", &fake)
        .env("FAKE_SSH_DIR", &w.root)
        .args(["copy", "k", "b.test", "--write-config"])
        .assert()
        .success();
    assert!(Path::new(&w.ssh_dir).join("ssk.d/k.conf").exists());
}

#[test]
fn ssh_dir_from_file_expands_tilde_against_home() {
    let w = world();
    write_config(&w, "ssh_dir = \"~/keys\"\n");
    ssk()
        .env("SSK_CONFIG", &w.config)
        .env("HOME", &w.root)
        .args(["new", "k", "--no-passphrase"])
        .assert()
        .success();
    assert!(w.root.join("keys/k").exists());
    assert_eq!(mode(&w.root.join("keys")), 0o700);
}

#[test]
fn ssh_dir_env_expands_tilde_against_home() {
    let w = world();
    ssk()
        .env("SSK_SSH_DIR", "~/envkeys")
        .env("HOME", &w.root)
        .args(["new", "k", "--no-passphrase"])
        .assert()
        .success();
    assert!(w.root.join("envkeys/k").exists());
}

#[test]
fn config_path_prints_the_override() {
    let w = world();
    cmd(&w)
        .args(["config", "path"])
        .assert()
        .success()
        .stdout(format!("{}\n", w.config.display()));
}

#[test]
fn config_set_creates_the_file_with_private_modes_and_typed_values() {
    let w = world();
    cmd(&w)
        .args(["config", "set", "default_type", "rsa"])
        .assert()
        .success();
    cmd(&w)
        .args(["config", "set", "rsa_bits", "3072"])
        .assert()
        .success();
    cmd(&w)
        .args(["config", "set", "add_to_agent", "yes"])
        .assert()
        .success();
    let text = fs::read_to_string(&w.config).unwrap();
    assert!(text.contains("default_type = \"rsa\""), "{text}");
    assert!(text.contains("rsa_bits = 3072"), "{text}");
    assert!(text.contains("add_to_agent = true"), "{text}");
    assert_eq!(mode(&w.config), 0o600);
    assert_eq!(mode(w.config.parent().unwrap()), 0o700);
}

#[test]
fn config_set_keeps_comments_and_rejects_bad_input_untouched() {
    let w = world();
    write_config(&w, "# mine\ndefault_type = \"rsa\" # keep\n");
    cmd(&w)
        .args(["config", "set", "rsa_bits", "2048"])
        .assert()
        .success();
    let text = fs::read_to_string(&w.config).unwrap();
    assert!(text.contains("# mine") && text.contains("# keep"), "{text}");
    cmd(&w)
        .args(["config", "set", "rsa_bits", "1234"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("rsa_bits"));
    cmd(&w)
        .args(["config", "set", "nope", "1"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown config key"));
    assert_eq!(fs::read_to_string(&w.config).unwrap(), text);
}

#[test]
fn config_get_shows_values_and_sources() {
    let w = world();
    write_config(&w, "default_type = \"rsa\"\n");
    cmd(&w)
        .args(["config", "get"])
        .assert()
        .success()
        .stdout(predicate::str::contains("default_type"))
        .stdout(predicate::str::contains("(file)"))
        .stdout(predicate::str::contains("(default)"))
        .stdout(predicate::str::contains("(flag)"));
    cmd(&w)
        .args(["config", "get", "default_type"])
        .assert()
        .success()
        .stdout("rsa\n");
    cmd(&w)
        .env("SSK_RSA_BITS", "2048")
        .args(["config", "get", "rsa_bits"])
        .assert()
        .success()
        .stdout("2048\n");
    cmd(&w)
        .env("SSK_RSA_BITS", "2048")
        .args(["config", "get"])
        .assert()
        .stdout(predicate::str::contains("(env)"));
    cmd(&w)
        .args(["config", "get", "nope"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown config key"));
}

#[test]
fn config_get_json() {
    let w = world();
    write_config(&w, "default_type = \"rsa\"\n");
    let out = cmd(&w).args(["config", "get", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["default_type"]["value"], "rsa");
    assert_eq!(v["default_type"]["source"], "file");
    assert_eq!(v["rsa_bits"]["value"], "4096");
    assert_eq!(v["rsa_bits"]["source"], "default");
    let out = cmd(&w)
        .args(["config", "get", "default_type", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["value"], "rsa");
    assert!(
        cmd(&w)
            .args(["config", "set", "x", "y", "--json"])
            .output()
            .unwrap()
            .status
            .code()
            == Some(2)
    );
}

#[test]
fn config_unset_removes_and_is_idempotent() {
    let w = world();
    write_config(&w, "default_type = \"rsa\"\nrsa_bits = 2048\n");
    cmd(&w)
        .args(["config", "unset", "rsa_bits"])
        .assert()
        .success();
    let text = fs::read_to_string(&w.config).unwrap();
    assert!(
        !text.contains("rsa_bits") && text.contains("default_type"),
        "{text}"
    );
    cmd(&w)
        .args(["config", "unset", "rsa_bits"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not set"));
}

#[test]
fn config_edit_runs_the_editor_and_revalidates() {
    let w = world();
    let editor = w.root.join("editor.sh");
    fs::write(
        &editor,
        "#!/bin/sh\nprintf '%s\\n' \"$EDIT_LINE\" >> \"$1\"\n",
    )
    .unwrap();
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o755)).unwrap();
    cmd(&w)
        .env("EDITOR", &editor)
        .env("EDIT_LINE", "rsa_bits = 2048")
        .args(["config", "edit"])
        .assert()
        .success();
    let text = fs::read_to_string(&w.config).unwrap();
    assert!(
        text.starts_with("# ssk configuration"),
        "template first:\n{text}"
    );
    assert!(text.contains("rsa_bits = 2048"), "{text}");
    cmd(&w)
        .env("VISUAL", &editor)
        .env("EDIT_LINE", "nonsense = 1")
        .args(["config", "edit"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("nonsense"));
}
