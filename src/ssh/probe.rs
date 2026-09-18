//! "Does this key already log in?" — the same check `ssh-copy-id` performs.

use std::io;
use std::path::Path;

use super::runner::{SshInvocation, SshOutput, SshRunner};
use super::target_args;
use crate::target::Target;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// The key authenticated.
    Installed,
    /// The server answered "Permission denied": reachable, key not accepted.
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
        "LogLevel=INFO",
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

pub fn classify(out: &SshOutput) -> ProbeResult {
    if out.success() {
        ProbeResult::Installed
    } else if out.stderr.contains("Permission denied") {
        ProbeResult::NotInstalled
    } else {
        ProbeResult::Error(out.stderr.trim().to_string())
    }
}

pub fn probe(
    runner: &dyn SshRunner,
    private_key: &Path,
    target: &Target,
    extra_options: &[String],
) -> io::Result<ProbeResult> {
    Ok(classify(&runner.run(&invocation(
        private_key,
        target,
        extra_options,
    ))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::runner::fake::{FakeSsh, denied, ok, unreachable};
    use std::path::Path;

    fn target() -> Target {
        Target {
            user: Some("deploy".into()),
            host: "h".into(),
            port: Some(2222),
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
                "LogLevel=INFO",
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
    fn classify_three_ways() {
        assert_eq!(classify(&ok()), ProbeResult::Installed);
        assert_eq!(classify(&denied()), ProbeResult::NotInstalled);
        match classify(&unreachable()) {
            ProbeResult::Error(msg) => assert!(msg.contains("No route to host")),
            other => panic!("{other:?}"),
        }
        let odd = SshOutput {
            code: Some(255),
            stdout: String::new(),
            stderr: "Host key verification failed.\n".into(),
        };
        assert_eq!(
            classify(&odd),
            ProbeResult::Error("Host key verification failed.".into())
        );
    }

    #[test]
    fn probe_runs_exactly_one_command() {
        let ssh = FakeSsh::new(vec![denied()]);
        let r = probe(&ssh, Path::new("/k/work"), &target(), &[]).unwrap();
        assert_eq!(r, ProbeResult::NotInstalled);
        assert_eq!(ssh.calls().len(), 1);
        assert_eq!(ssh.calls()[0].args.last().map(String::as_str), Some("exit"));
    }
}
