mod common;
use common::ssk;
use predicates::prelude::*;

#[test]
fn help_lists_every_phase_one_subcommand() {
    let out = ssk().arg("--help").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for sub in ["new", "copy", "list", "show", "doctor", "completions"] {
        assert!(stdout.contains(sub), "missing `{sub}` in:\n{stdout}");
    }
}

#[test]
fn new_help_shows_passphrase_flags() {
    ssk()
        .args(["new", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("-N, --passphrase"))
        .stdout(predicate::str::contains("--no-passphrase"))
        .stdout(predicate::str::contains("--passphrase-stdin"))
        .stdout(predicate::str::contains("-t, --type"));
}

#[test]
fn completions_zsh_emits_a_script() {
    ssk()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef ssk"));
}

#[test]
fn copy_requires_at_least_one_target() {
    ssk().args(["copy", "work"]).assert().code(2);
}

#[test]
fn help_lists_every_subcommand() {
    let out = ssk().arg("--help").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for sub in [
        "new",
        "copy",
        "list",
        "show",
        "doctor",
        "completions",
        "add",
        "rm",
        "rename",
        "revoke",
        "config",
        "rotate",
        "hosts",
    ] {
        assert!(stdout.contains(sub), "missing `{sub}` in:\n{stdout}");
    }
}

#[test]
fn json_is_a_usage_error_where_unsupported() {
    ssk()
        .args(["--json", "new", "x"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "--json is not supported by `ssk new`",
        ));
}

#[test]
fn revoke_needs_targets_or_all_but_not_both() {
    ssk().args(["revoke", "work"]).assert().code(2);
    ssk()
        .args(["revoke", "work", "--all", "h"])
        .assert()
        .code(2);
}

#[test]
fn config_help_lists_every_action() {
    let out = ssk().args(["config", "--help"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for a in ["path", "get", "set", "unset", "edit"] {
        assert!(stdout.contains(a), "missing `{a}` in:\n{stdout}");
    }
}

#[test]
fn new_and_copy_have_the_override_flags() {
    ssk()
        .args(["new", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--no-add"));
    ssk()
        .args(["copy", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--write-config"));
    ssk()
        .args(["new", "x", "--add", "--no-add"])
        .assert()
        .code(2);
    ssk()
        .args(["copy", "x", "h", "--no-config", "--write-config"])
        .assert()
        .code(2);
}

#[test]
fn completions_mention_new_subcommands() {
    ssk()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rotate"))
        .stdout(predicate::str::contains("revoke"));
}
