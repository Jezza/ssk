//! The one seam between ssk and the network: an `SshRunner` runs an `ssh` argv.
//! Production uses `RealSsh`; tests use `fake::FakeSsh`.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;

use crate::ui::shell_join;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInvocation {
    /// Arguments after the program name.
    pub args: Vec<String>,
    /// Fed to the child's stdin when `Some`; otherwise stdin is inherited.
    pub stdin: Option<String>,
    /// Capture stdout/stderr (probe) instead of inheriting them (install).
    pub capture: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshOutput {
    /// Exit code; `None` if killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl SshOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

pub trait SshRunner {
    fn run(&self, inv: &SshInvocation) -> io::Result<SshOutput>;
}

pub struct RealSsh {
    program: PathBuf,
    verbose: u8,
}

impl RealSsh {
    /// `SSK_SSH_BIN` if set (tests), else `ssh` from PATH.
    pub fn locate(verbose: u8) -> anyhow::Result<RealSsh> {
        Self::locate_with(std::env::var_os("SSK_SSH_BIN").as_deref(), verbose)
    }

    pub fn locate_with(override_bin: Option<&OsStr>, verbose: u8) -> anyhow::Result<RealSsh> {
        let program = match override_bin {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => {
                which::which("ssh").context("`ssh` not found on PATH; install an OpenSSH client")?
            }
        };
        Ok(RealSsh { program, verbose })
    }

    pub fn with_program(program: PathBuf, verbose: u8) -> RealSsh {
        RealSsh { program, verbose }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }
}

impl SshRunner for RealSsh {
    fn run(&self, inv: &SshInvocation) -> io::Result<SshOutput> {
        let mut args = inv.args.clone();
        if self.verbose >= 2 {
            args.insert(0, "-v".to_string());
        }
        if self.verbose >= 1 {
            eprintln!("$ {} {}", self.program.display(), shell_join(&args));
        }
        let mut cmd = Command::new(&self.program);
        cmd.args(&args);
        cmd.stdin(if inv.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        if inv.capture {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        }
        let mut child = cmd.spawn()?;
        if let Some(input) = &inv.stdin {
            let mut stdin = child.stdin.take().expect("stdin was piped");
            stdin.write_all(input.as_bytes())?;
            // dropping `stdin` closes the pipe so the remote `read` sees EOF after the line
        }
        let out = child.wait_with_output()?;
        Ok(SshOutput {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Records every invocation and replays scripted outputs in order.
    pub struct FakeSsh {
        calls: RefCell<Vec<SshInvocation>>,
        responses: RefCell<VecDeque<SshOutput>>,
    }

    impl FakeSsh {
        pub fn new(responses: Vec<SshOutput>) -> FakeSsh {
            FakeSsh {
                calls: RefCell::new(Vec::new()),
                responses: RefCell::new(responses.into()),
            }
        }

        pub fn calls(&self) -> Vec<SshInvocation> {
            self.calls.borrow().clone()
        }
    }

    impl SshRunner for FakeSsh {
        fn run(&self, inv: &SshInvocation) -> io::Result<SshOutput> {
            self.calls.borrow_mut().push(inv.clone());
            Ok(self
                .responses
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("FakeSsh: unexpected call {:?}", inv.args)))
        }
    }

    pub fn ok() -> SshOutput {
        SshOutput {
            code: Some(0),
            ..Default::default()
        }
    }

    pub fn denied() -> SshOutput {
        SshOutput {
            code: Some(255),
            stdout: String::new(),
            stderr: "deploy@h: Permission denied (publickey).\n".to_string(),
        }
    }

    pub fn unreachable() -> SshOutput {
        SshOutput {
            code: Some(255),
            stdout: String::new(),
            stderr: "ssh: connect to host h port 22: No route to host\n".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn real_ssh_captures_output_and_feeds_stdin() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("fake");
        std::fs::write(
            &script,
            "#!/bin/sh\necho out-$1\ncat\necho err >&2\nexit 3\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ssh = RealSsh::with_program(script, 0);
        let out = ssh
            .run(&SshInvocation {
                args: vec!["A".into()],
                stdin: Some("in\n".into()),
                capture: true,
            })
            .unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout, "out-A\nin\n");
        assert_eq!(out.stderr, "err\n");
        assert!(!out.success());
    }

    #[test]
    fn locate_honours_override() {
        let ssh = RealSsh::locate_with(Some(std::ffi::OsStr::new("/opt/bin/ssh")), 0).unwrap();
        assert_eq!(ssh.program(), std::path::Path::new("/opt/bin/ssh"));
    }

    #[test]
    fn fake_records_calls_and_replays_responses() {
        let f = fake::FakeSsh::new(vec![fake::ok(), fake::denied()]);
        let inv = SshInvocation {
            args: vec!["x".into()],
            stdin: None,
            capture: true,
        };
        assert!(f.run(&inv).unwrap().success());
        assert!(f.run(&inv).unwrap().stderr.contains("Permission denied"));
        assert_eq!(f.calls().len(), 2);
    }
}
