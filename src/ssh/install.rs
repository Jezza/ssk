//! Append a public key to a host's authorized_keys by running the vendored
//! ssh-copy-id snippet over ssh, with the key on stdin.

use std::io;
use std::path::Path;

use super::runner::{SshInvocation, SshOutput, SshRunner};
use super::{identities_only, target_args};
use crate::target::Target;

/// The snippet as vendored, comments included. See `install_snippet.sh` for provenance.
pub const SNIPPET_SOURCE: &str = include_str!("install_snippet.sh");

/// Drop comment and blank lines, trim, and join with single spaces. Upstream does the
/// same (`tr -s '\t\n' ' '`) so the command survives tcsh and friends as one line.
pub fn squash(source: &str) -> String {
    source
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Force a POSIX shell on the remote regardless of the user's login shell.
pub fn remote_command() -> String {
    format!("exec sh -c '{}'", squash(SNIPPET_SOURCE))
}

/// ssh argv for the install step. Any auth that works (a config key, a default key, a
/// password) is fine for getting the new key on; `IdentitiesOnly=yes` only stops ssh
/// burning `MaxAuthTries` on agent keys first (see [`identities_only`]). `auth_key` adds
/// one `-i` to try first; `rotate` passes the current key.
pub fn invocation(
    target: &Target,
    extra_options: &[String],
    public_key_line: &str,
    auth_key: Option<&Path>,
) -> SshInvocation {
    let mut args = vec!["-o".to_string(), "ControlPath=none".to_string()];
    if let Some(k) = auth_key {
        args.push("-i".to_string());
        args.push(k.display().to_string());
    }
    args.extend(target_args(target, extra_options));
    args.extend(identities_only());
    args.push("--".to_string());
    args.push(target.host.clone());
    args.push(remote_command());
    SshInvocation {
        args,
        stdin: Some(format!("{}\n", public_key_line.trim())),
        capture: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallResult {
    Installed,
    Failed { code: Option<i32> },
}

pub fn install(
    runner: &dyn SshRunner,
    target: &Target,
    extra_options: &[String],
    public_key_line: &str,
    auth_key: Option<&Path>,
) -> io::Result<InstallResult> {
    let out: SshOutput = runner.run(&invocation(
        target,
        extra_options,
        public_key_line,
        auth_key,
    ))?;
    Ok(if out.success() {
        InstallResult::Installed
    } else {
        InstallResult::Failed { code: out.code }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::runner::fake::{FakeSsh, ok};
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn squashed_snippet_is_one_safe_line() {
        let s = squash(SNIPPET_SOURCE);
        assert!(!s.contains('\n'));
        assert!(
            !s.contains('\''),
            "a single quote would break the exec sh -c '...' wrapper:\n{s}"
        );
        assert!(
            !s.contains('#'),
            "a # would comment out the rest of the one-liner:\n{s}"
        );
        assert!(s.starts_with("cd; umask 077;"), "{s}");
        assert!(s.contains("grep -qxF -- \"$k\""), "{s}");
        assert!(s.contains("restorecon"), "{s}");
        assert!(s.contains("/etc/dropbear/authorized_keys"), "{s}");
    }

    #[test]
    fn remote_command_is_wrapped_in_exec_sh() {
        let c = remote_command();
        assert!(c.starts_with("exec sh -c '"));
        assert!(c.ends_with('\''));
    }

    #[test]
    fn invocation_has_no_identity_flag_and_feeds_key_on_stdin() {
        let t = Target {
            user: Some("u".into()),
            host: "h".into(),
            port: None,
        };
        let inv = invocation(
            &t,
            &["ProxyJump=b".to_string()],
            "ssh-ed25519 AAAA c\n",
            None,
        );
        let expected: Vec<String> = [
            "-o",
            "ControlPath=none",
            "-l",
            "u",
            "-o",
            "ProxyJump=b",
            "-o",
            "IdentitiesOnly=yes",
            "--",
            "h",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::once(remote_command()))
        .collect();
        assert_eq!(inv.args, expected);
        assert_eq!(inv.stdin.as_deref(), Some("ssh-ed25519 AAAA c\n"));
        assert!(!inv.capture);
        assert!(!inv.args.iter().any(|a| a == "-i"));
    }

    #[test]
    fn install_maps_exit_status() {
        let t = Target {
            user: None,
            host: "h".into(),
            port: None,
        };
        let ssh = FakeSsh::new(vec![
            ok(),
            SshOutput {
                code: Some(255),
                ..Default::default()
            },
        ]);
        assert_eq!(
            install(&ssh, &t, &[], "k", None).unwrap(),
            InstallResult::Installed
        );
        assert_eq!(
            install(&ssh, &t, &[], "k", None).unwrap(),
            InstallResult::Failed { code: Some(255) }
        );
    }

    #[test]
    fn auth_key_adds_a_single_i_and_keeps_identities_only() {
        let t = Target {
            user: None,
            host: "h".into(),
            port: None,
        };
        let inv = invocation(&t, &[], "k", Some(Path::new("/k/old")));
        assert_eq!(&inv.args[..4], &["-o", "ControlPath=none", "-i", "/k/old"]);
        assert!(inv.args.iter().any(|a| a == "IdentitiesOnly=yes"));
    }

    /// ssh keeps the first value it sees for an option, so ours must come after the user's.
    #[test]
    fn a_user_identities_only_option_outranks_ours() {
        let t = Target {
            user: None,
            host: "h".into(),
            port: None,
        };
        let inv = invocation(&t, &["IdentitiesOnly=no".to_string()], "k", None);
        let at = |v: &str| {
            inv.args
                .iter()
                .position(|a| a == v)
                .unwrap_or_else(|| panic!("{v} missing from {:?}", inv.args))
        };
        assert!(at("IdentitiesOnly=no") < at("IdentitiesOnly=yes"));
    }

    /// Runs the real snippet under `sh` with HOME pointed at a temp dir. This is
    /// the test that proves the vendored shell still does what ssh-copy-id does.
    #[test]
    fn snippet_installs_idempotently_in_a_fake_home() {
        let home = tempfile::tempdir().unwrap();
        let run = |line: &str| {
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(squash(SNIPPET_SOURCE))
                .env("HOME", home.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(line.as_bytes())
                .unwrap();
            let status = child.wait().unwrap();
            assert!(status.success(), "{status}");
        };
        let ak = home.path().join(".ssh/authorized_keys");

        run("ssh-ed25519 AAAA one\n");
        assert_eq!(
            std::fs::read_to_string(&ak).unwrap(),
            "ssh-ed25519 AAAA one\n"
        );
        assert_eq!(crate::fsx::mode_of(&ak).unwrap(), 0o600);
        assert_eq!(
            crate::fsx::mode_of(&home.path().join(".ssh")).unwrap(),
            0o700
        );

        run("ssh-ed25519 AAAA one\n"); // same key again: no duplicate
        assert_eq!(
            std::fs::read_to_string(&ak).unwrap(),
            "ssh-ed25519 AAAA one\n"
        );

        std::fs::write(&ak, "ssh-ed25519 AAAA one\nno-trailing-newline").unwrap();
        run("ssh-ed25519 BBBB two\n"); // missing newline is repaired before appending
        assert_eq!(
            std::fs::read_to_string(&ak).unwrap(),
            "ssh-ed25519 AAAA one\nno-trailing-newline\nssh-ed25519 BBBB two\n"
        );
    }
}
