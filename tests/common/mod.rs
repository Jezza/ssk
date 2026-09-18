#![allow(dead_code)]
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// A `ssk` command with a clean environment: no agent, no inherited ssh dir, no colour.
pub fn ssk() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_ssk"));
    cmd.env_remove("SSH_AUTH_SOCK")
        .env_remove("SSK_SSH_DIR")
        .env_remove("SSK_SSH_BIN")
        .env("NO_COLOR", "1");
    cmd
}

/// Permission bits of `path`, e.g. 0o600.
pub fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}
