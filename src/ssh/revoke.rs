//! Remove a public key from a host's authorized_keys by running ssk's revoke snippet
//! over ssh with the key line on stdin. The counterpart of `install`.

use std::io;
use std::path::Path;

use super::install::squash;
use super::runner::{SshInvocation, SshOutput, SshRunner};
use super::target_args;
use crate::target::Target;

pub const SNIPPET_SOURCE: &str = include_str!("revoke_snippet.sh");

/// The snippet's exit status for "no such key here".
pub const NOT_PRESENT_EXIT: i32 = 3;

pub fn remote_command() -> String {
    format!("exec sh -c '{}'", squash(SNIPPET_SOURCE))
}

/// `-i auth_key` *without* IdentitiesOnly: that key first, then whatever else ssh would
/// try (agent, defaults, password), so revoking your only key still gets you in.
pub fn invocation(
    auth_key: &Path,
    target: &Target,
    extra_options: &[String],
    public_key_line: &str,
) -> SshInvocation {
    let mut args = vec![
        "-o".to_string(),
        "ControlPath=none".to_string(),
        "-i".to_string(),
        auth_key.display().to_string(),
    ];
    args.extend(target_args(target, extra_options));
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
pub enum RevokeResult {
    Removed,
    NotPresent,
    /// 255 is ssh itself (connect or auth); anything else is the remote snippet.
    Failed {
        code: Option<i32>,
    },
}

pub fn classify(out: &SshOutput) -> RevokeResult {
    match out.code {
        Some(0) => RevokeResult::Removed,
        Some(NOT_PRESENT_EXIT) => RevokeResult::NotPresent,
        code => RevokeResult::Failed { code },
    }
}

pub fn revoke(
    runner: &dyn SshRunner,
    auth_key: &Path,
    target: &Target,
    extra_options: &[String],
    public_key_line: &str,
) -> io::Result<RevokeResult> {
    Ok(classify(&runner.run(&invocation(
        auth_key,
        target,
        extra_options,
        public_key_line,
    ))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::install;
    use crate::ssh::runner::fake::{FakeSsh, ok};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    #[test]
    fn squashed_snippet_is_one_safe_line() {
        let s = install::squash(SNIPPET_SOURCE);
        assert!(!s.contains('\n'));
        assert!(
            !s.contains('\''),
            "single quote would break exec sh -c '...':\n{s}"
        );
        assert!(!s.contains('#'), "# would comment out the rest:\n{s}");
        assert!(s.starts_with("cd; umask 077;"), "{s}");
        assert!(s.contains("exit 3"), "{s}");
        assert!(s.contains("grep -vF -- \" $b\""), "{s}");
        assert!(s.contains("/etc/dropbear/authorized_keys"), "{s}");
        assert!(s.contains("restorecon"), "{s}");
    }

    #[test]
    fn invocation_authenticates_with_the_key_and_feeds_it_on_stdin() {
        let t = Target {
            user: Some("u".into()),
            host: "h".into(),
            port: Some(2222),
        };
        let inv = invocation(
            Path::new("/k/work"),
            &t,
            &["ProxyJump=b".to_string()],
            "ssh-ed25519 AAAA c\n",
        );
        let expected: Vec<String> = [
            "-o",
            "ControlPath=none",
            "-i",
            "/k/work",
            "-p",
            "2222",
            "-l",
            "u",
            "-o",
            "ProxyJump=b",
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
        assert!(!inv.args.iter().any(|a| a.contains("IdentitiesOnly")));
    }

    #[test]
    fn classify_maps_exit_codes() {
        let with = |code| SshOutput {
            code,
            ..Default::default()
        };
        assert_eq!(classify(&ok()), RevokeResult::Removed);
        assert_eq!(classify(&with(Some(3))), RevokeResult::NotPresent);
        assert_eq!(
            classify(&with(Some(255))),
            RevokeResult::Failed { code: Some(255) }
        );
        assert_eq!(classify(&with(None)), RevokeResult::Failed { code: None });
        let ssh = FakeSsh::new(vec![with(Some(3))]);
        let t = Target {
            user: None,
            host: "h".into(),
            port: None,
        };
        assert_eq!(
            revoke(&ssh, Path::new("/k"), &t, &[], "k").unwrap(),
            RevokeResult::NotPresent
        );
        assert_eq!(ssh.calls().len(), 1);
    }

    /// Runs the real snippets under `sh` with HOME in a temp dir: install two keys with the
    /// vendored install snippet, then revoke by blob with ours.
    #[test]
    fn snippet_removes_by_blob_and_reports_absence() {
        let home = tempfile::tempdir().unwrap();
        let run = |snippet: &str, line: &str| -> i32 {
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(install::squash(snippet))
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
            child.wait().unwrap().code().unwrap()
        };
        let ak = home.path().join(".ssh/authorized_keys");
        let read = || fs::read_to_string(&ak).unwrap_or_default();

        assert_eq!(run(install::SNIPPET_SOURCE, "ssh-ed25519 AAAAone one\n"), 0);
        assert_eq!(run(install::SNIPPET_SOURCE, "ssh-ed25519 AAAAtwo two\n"), 0);
        assert_eq!(read().lines().count(), 2);

        // a different comment still matches: we match the blob, not the line
        assert_eq!(
            run(SNIPPET_SOURCE, "ssh-ed25519 AAAAone another-comment\n"),
            0
        );
        assert_eq!(read(), "ssh-ed25519 AAAAtwo two\n");
        assert_eq!(
            fs::metadata(&ak).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            run(SNIPPET_SOURCE, "ssh-ed25519 AAAAone one\n"),
            3,
            "already gone"
        );
        assert_eq!(run(SNIPPET_SOURCE, "ssh-ed25519 AAAAtwo two\n"), 0);
        assert_eq!(read(), "", "emptying the file is a valid outcome");
        assert_eq!(run(SNIPPET_SOURCE, "ssh-ed25519 AAAAtwo two\n"), 3);
        fs::remove_file(&ak).unwrap();
        assert_eq!(
            run(SNIPPET_SOURCE, "ssh-ed25519 AAAAtwo two\n"),
            3,
            "no file at all"
        );
        assert!(
            fs::read_dir(home.path().join(".ssh")).unwrap().count() == 0,
            "no temp files left behind"
        );
    }
}
