//! "Does this key already log in?" — the same check `ssh-copy-id` performs, plus proof
//! that the key *we* asked for is the one the server accepted.

use std::io;
use std::path::Path;

use super::runner::{SshInvocation, SshOutput, SshRunner};
use super::target_args;
use crate::target::Target;

/// The debug line OpenSSH prints for the key that authenticated. Matched
/// case-insensitively: it has been logged both as `Server accepts key:` and as
/// `input_userauth_pk_ok: server accepts key:`.
const ACCEPTS: &str = "server accepts key:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// The key authenticated.
    Installed,
    /// The server answered "Permission denied", or let us in on some *other* key.
    NotInstalled,
    /// Anything else (unreachable, host key changed, DNS...). ssh's stderr, trimmed.
    Error(String),
}

pub fn invocation(private_key: &Path, target: &Target, extra_options: &[String]) -> SshInvocation {
    let mut args: Vec<String> = [
        "-i",
        &private_key.display().to_string(),
        "-o",
        "ControlPath=none",
        "-o",
        "LogLevel=DEBUG1",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "IdentitiesOnly=yes",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(target_args(target, extra_options));
    args.push("--".to_string());
    args.push(target.host.clone());
    args.push("exit".to_string());
    SshInvocation {
        args,
        stdin: None,
        capture: true,
    }
}

/// Exit 0 is *not* enough: `IdentitiesOnly=yes` only stops ssh offering agent keys, while
/// every `IdentityFile` line the ssh config matches for this host is still tried after the
/// `-i` key. ssk's own `ssk.d/<name>.conf` (Included from `~/.ssh/config`) carries exactly
/// such a line, so a probe with `-i work.new` can come back 0 because `work` — a different
/// key entirely — was accepted, and `--force`-less `copy`, `rotate` and `revoke --all`
/// would all draw the wrong conclusion. So the probe runs at `LogLevel=DEBUG1` and only
/// believes the key is installed when ssh names it in its `server accepts key:` line,
/// either by the path we passed to `-i` or by fingerprint. OpenSSH has printed that line
/// since 8.x; an older client never reports `Installed`, which is the safe direction.
pub fn classify(out: &SshOutput, key_path: &Path, fingerprint: &str) -> ProbeResult {
    if out.success() {
        if accepted(&out.stderr, key_path, fingerprint) {
            ProbeResult::Installed
        } else {
            ProbeResult::NotInstalled
        }
    } else if out.stderr.contains("Permission denied") {
        ProbeResult::NotInstalled
    } else {
        ProbeResult::Error(error_message(&out.stderr))
    }
}

/// Did ssh report accepting *this* key? `to_ascii_lowercase` keeps byte offsets, so the
/// index found in the lowered copy indexes the original line.
fn accepted(stderr: &str, key_path: &Path, fingerprint: &str) -> bool {
    let key = key_path.display().to_string();
    stderr
        .lines()
        .filter_map(|line| {
            let at = line.to_ascii_lowercase().find(ACCEPTS)?;
            Some(&line[at + ACCEPTS.len()..])
        })
        .any(|rest| {
            (!key.is_empty() && rest.split_whitespace().next() == Some(key.as_str()))
                || (!fingerprint.is_empty() && rest.contains(fingerprint))
        })
}

/// ssh runs at `LogLevel=DEBUG1` so it can name the accepted key (see `accepted` above),
/// which fills stderr with `debug1: ...` chatter that isn't fit to show a user. Report the
/// last non-empty, non-`debugN:` line instead — the actual failure ssh printed — falling
/// back to the whole trimmed stderr if every line is debug output (or there is none).
fn error_message(stderr: &str) -> String {
    let trimmed = stderr.trim();
    trimmed
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty() && !is_debug_line(line))
        .map(str::to_string)
        .unwrap_or_else(|| trimmed.to_string())
}

/// Matched case-insensitively, same as `ACCEPTS`: `debug1:`/`debug2:`/`debug3:`.
fn is_debug_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ["debug1:", "debug2:", "debug3:"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

pub fn probe(
    runner: &dyn SshRunner,
    private_key: &Path,
    fingerprint: &str,
    target: &Target,
    extra_options: &[String],
) -> io::Result<ProbeResult> {
    let out = runner.run(&invocation(private_key, target, extra_options))?;
    Ok(classify(&out, private_key, fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::runner::fake::{FakeSsh, accepts, denied, ok, unreachable};
    use std::path::Path;

    fn target() -> Target {
        Target {
            user: Some("deploy".into()),
            host: "h".into(),
            port: Some(2222),
        }
    }

    fn accepted_line(line: &str) -> SshOutput {
        SshOutput {
            code: Some(0),
            stdout: String::new(),
            stderr: format!("debug1: Authenticating to h:2222 as 'deploy'\n{line}\n"),
        }
    }

    #[test]
    fn invocation_matches_ssh_copy_id_probe() {
        let inv = invocation(
            Path::new("/k/work"),
            &target(),
            &["ProxyJump=b".to_string()],
        );
        assert_eq!(
            inv.args,
            vec![
                "-i",
                "/k/work",
                "-o",
                "ControlPath=none",
                "-o",
                "LogLevel=DEBUG1",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "IdentitiesOnly=yes",
                "-p",
                "2222",
                "-l",
                "deploy",
                "-o",
                "ProxyJump=b",
                "--",
                "h",
                "exit",
            ]
        );
        assert!(inv.capture);
        assert_eq!(inv.stdin, None);
    }

    #[test]
    fn success_counts_only_when_ssh_names_the_probed_key() {
        let out = accepted_line("debug1: Server accepts key: /k/work ED25519 SHA256:abc explicit");
        assert_eq!(
            classify(&out, Path::new("/k/work"), "SHA256:abc"),
            ProbeResult::Installed,
            "named by path"
        );
        assert_eq!(
            classify(&out, Path::new("/k/other"), "SHA256:zzz"),
            ProbeResult::NotInstalled,
            "another key got in: config IdentityFile lines are tried after -i"
        );
        assert_eq!(
            classify(
                &accepted_line(
                    "debug1: input_userauth_pk_ok: server accepts key: /k/work ED25519 SHA256:abc explicit"
                ),
                Path::new("/k/work"),
                "SHA256:abc"
            ),
            ProbeResult::Installed,
            "the older wording, matched case-insensitively"
        );
        assert_eq!(
            classify(
                &accepted_line(
                    "debug1: Server accepts key: /elsewhere/copy ED25519 SHA256:abc agent"
                ),
                Path::new("/k/work"),
                "SHA256:abc"
            ),
            ProbeResult::Installed,
            "same key material under another path: the fingerprint decides"
        );
        assert_eq!(
            classify(&ok(), Path::new("/k/work"), "SHA256:abc"),
            ProbeResult::NotInstalled,
            "exit 0 with no accepts line proves nothing about our key"
        );
        assert_eq!(
            classify(
                &accepted_line("debug1: Server accepts key: /k/work2 ED25519 SHA256:zzz explicit"),
                Path::new("/k/work"),
                "SHA256:abc"
            ),
            ProbeResult::NotInstalled,
            "path match must be anchored: /k/work2 is not /k/work, foreign fingerprint too"
        );
        assert_eq!(
            classify(
                &accepted_line("debug1: Server accepts key: /k/work ED25519 SHA256:abc explicit"),
                Path::new("/k/work"),
                "SHA256:abc"
            ),
            ProbeResult::Installed,
            "exact path match"
        );
    }

    #[test]
    fn failures_are_told_apart() {
        let k = Path::new("/k/work");
        assert_eq!(
            classify(&denied(), k, "SHA256:abc"),
            ProbeResult::NotInstalled
        );
        match classify(&unreachable(), k, "SHA256:abc") {
            ProbeResult::Error(msg) => assert!(msg.contains("No route to host")),
            other => panic!("{other:?}"),
        }
        let odd = SshOutput {
            code: Some(255),
            stdout: String::new(),
            stderr: "Host key verification failed.\n".into(),
        };
        assert_eq!(
            classify(&odd, k, "SHA256:abc"),
            ProbeResult::Error("Host key verification failed.".into())
        );
    }

    #[test]
    fn error_strips_the_debug1_transcript_down_to_sshs_last_line() {
        let out = SshOutput {
            code: Some(255),
            stdout: String::new(),
            stderr: "debug1: Reading configuration data /etc/ssh/ssh_config\n\
                     debug1: Connecting to h [1.2.3.4] port 22.\n\
                     ssh: connect to host h port 22: Connection refused\n"
                .to_string(),
        };
        assert_eq!(
            classify(&out, Path::new("/k/work"), "SHA256:abc"),
            ProbeResult::Error("ssh: connect to host h port 22: Connection refused".into())
        );
    }

    #[test]
    fn error_falls_back_to_the_whole_trimmed_stderr_when_only_debug_lines() {
        let stderr = "debug1: Reading configuration data /etc/ssh/ssh_config\n\
                       debug2: match not found\n"
            .to_string();
        let out = SshOutput {
            code: Some(255),
            stdout: String::new(),
            stderr: stderr.clone(),
        };
        assert_eq!(
            classify(&out, Path::new("/k/work"), "SHA256:abc"),
            ProbeResult::Error(stderr.trim().to_string())
        );
    }

    #[test]
    fn probe_runs_exactly_one_command() {
        let ssh = FakeSsh::new(vec![denied()]);
        let r = probe(&ssh, Path::new("/k/work"), "SHA256:abc", &target(), &[]).unwrap();
        assert_eq!(r, ProbeResult::NotInstalled);
        assert_eq!(ssh.calls().len(), 1);
        assert_eq!(ssh.calls()[0].args.last().map(String::as_str), Some("exit"));

        let ssh = FakeSsh::new(vec![accepts(Path::new("/k/work"))]);
        assert_eq!(
            probe(&ssh, Path::new("/k/work"), "SHA256:abc", &target(), &[]).unwrap(),
            ProbeResult::Installed
        );
    }
}
