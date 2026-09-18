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
