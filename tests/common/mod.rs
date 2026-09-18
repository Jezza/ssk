#![allow(dead_code)]
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// A `ssk` command with a clean environment: no agent, no inherited ssh dir, no colour.
pub fn ssk() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_ssk"));
    cmd.env_remove("SSH_AUTH_SOCK")
        .env_remove("SSK_SSH_DIR")
        .env_remove("SSK_SSH_BIN")
        .env_remove("SSK_SSH_ADD_BIN")
        .env("SSK_CONFIG", "/nonexistent/ssk/config.toml")
        .env("NO_COLOR", "1");
    cmd
}

/// Permission bits of `path`, e.g. 0o600.
pub fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

use std::path::PathBuf;

/// A stand-in `ssh`. Every argv is appended to `$FAKE_SSH_DIR/args.log`. Each host gets
/// a fake home at `$FAKE_SSH_DIR/home-<host>` and the remote command (ssk's install or
/// revoke snippet, `exec sh -c '...'`) really runs there under `sh`, with stdin also
/// copied to `stdin.log`. A probe (last argument `exit`) succeeds when that home's
/// authorized_keys carries the blob from the `-i` key's `.pub`, and then prints the
/// `Server accepts key:` debug line ssk's probe insists on.
/// `FAKE_SSH_FAIL_HOST=<host>` refuses every connection to that host;
/// `FAKE_SSH_FAIL_REVOKE=1` makes the revoke snippet fail with exit 1.
pub fn fake_ssh(dir: &Path) -> PathBuf {
    let script = dir.join("fake-ssh");
    fs::write(
        &script,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_SSH_DIR/args.log"
host=""; key=""; prev=""; last=""
for a in "$@"; do
  if [ "$prev" = "--" ] && [ -z "$host" ]; then host="$a"; fi
  if [ "$prev" = "-i" ]; then key="$a"; fi
  prev="$a"; last="$a"
done
if [ -n "$FAKE_SSH_FAIL_HOST" ] && [ "$host" = "$FAKE_SSH_FAIL_HOST" ]; then
  echo "ssh: connect to host $host port 22: Connection refused" >&2
  exit 255
fi
HOME="$FAKE_SSH_DIR/home-$host"; export HOME; mkdir -p "$HOME"
if [ "$last" = "exit" ]; then
  blob=$(awk '{print $2}' "$key.pub")
  if [ -f "$HOME/.ssh/authorized_keys" ] && grep -qF -- " $blob" "$HOME/.ssh/authorized_keys"; then
    echo "debug1: Server accepts key: $key ED25519 SHA256:fake explicit" >&2
    exit 0
  fi
  echo "deploy@$host: Permission denied (publickey)." >&2
  exit 255
fi
case "$last" in
  *"grep -vF"*) if [ -n "$FAKE_SSH_FAIL_REVOKE" ]; then echo "remote: disk on fire" >&2; exit 1; fi;;
esac
cat > "$FAKE_SSH_DIR/stdin.log"
sh -c "$last" < "$FAKE_SSH_DIR/stdin.log"
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

/// A stand-in `ssh` whose host is never reachable.
pub fn unreachable_ssh(dir: &Path) -> PathBuf {
    let script = dir.join("down-ssh");
    fs::write(
        &script,
        "#!/bin/sh\necho 'ssh: connect to host example.test port 22: No route to host' >&2\nexit 255\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

/// A stand-in `ssh-add`. Every argv is appended to `$FAKE_AGENT_DIR/ssh-add.log`.
/// `-l` prints `$FAKE_AGENT_DIR/loaded` when that file is non-empty, otherwise the real
/// "no identities" message with exit 1. Adding fails when `FAKE_SSH_ADD_FAIL` is set.
pub fn fake_ssh_add(dir: &Path) -> PathBuf {
    let script = dir.join("fake-ssh-add");
    fs::write(
        &script,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_AGENT_DIR/ssh-add.log"
case "$1" in
  -l)
    if [ -s "$FAKE_AGENT_DIR/loaded" ]; then cat "$FAKE_AGENT_DIR/loaded"; exit 0; fi
    echo "The agent has no identities."; exit 1;;
  -d) exit 0;;
  *)
    if [ -n "$FAKE_SSH_ADD_FAIL" ]; then echo "Could not add identity" >&2; exit 1; fi
    exit 0;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}
