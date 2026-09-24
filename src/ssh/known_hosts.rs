//! Forget a host's recorded key, for `copy --replace-host-key` after a reinstall. ssh
//! itself says which name and files apply (`ssh -G`), and `ssh-keygen -R` does the
//! removal, so hashed entries, `HostKeyAlias` and `UserKnownHostsFile` all just work.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::runner::{SshInvocation, SshRunner};
use super::target_args;
use crate::target::Target;

/// Where ssh looks up a host's key: the name it is recorded under and the user files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// `host`, `[host]:port` off port 22, or the `HostKeyAlias` as is.
    pub name: String,
    pub files: Vec<PathBuf>,
}

/// `ssh -G` resolves the target through the ssh config without connecting.
pub fn invocation(target: &Target, extra_options: &[String]) -> SshInvocation {
    let mut args = vec!["-G".to_string()];
    args.extend(target_args(target, extra_options));
    args.push("--".to_string());
    args.push(target.host.clone());
    SshInvocation {
        args,
        stdin: None,
        capture: true,
    }
}

pub fn parse(stdout: &str) -> Lookup {
    let value = |key: &str| {
        stdout.lines().find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == key).then(|| v.trim())
        })
    };
    let name = match (value("hostkeyalias"), value("hostname"), value("port")) {
        (Some(alias), _, _) => alias.to_string(),
        (None, Some(host), Some(port)) if port != "22" => format!("[{host}]:{port}"),
        (None, host, _) => host.unwrap_or_default().to_string(),
    };
    let files = value("userknownhostsfile")
        .unwrap_or_default()
        .split_whitespace()
        .filter(|f| *f != "none")
        .map(PathBuf::from)
        .collect();
    Lookup { name, files }
}

/// `SSK_SSH_KEYGEN_BIN` if set (tests), else `ssh-keygen` from PATH.
pub fn keygen_program() -> PathBuf {
    std::env::var_os("SSK_SSH_KEYGEN_BIN")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ssh-keygen"))
}

/// Remove `name` from `file`; `true` if an entry was there. `ssh-keygen` keeps the old
/// contents as `<file>.old`.
pub fn remove(keygen: &Path, name: &str, file: &Path) -> io::Result<bool> {
    let out = Command::new(keygen)
        .arg("-R")
        .arg(name)
        .arg("-f")
        .arg(file)
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "ssh-keygen -R {name} -f {}: {}",
            file.display(),
            stderr.trim()
        )));
    }
    // "# Host <name> found: line 3", once per entry removed.
    Ok(stdout.lines().any(|l| l.contains(" found: line ")))
}

/// Remove the target's entry from every user known_hosts file that has one. Returns the
/// lookup and the files that changed.
pub fn forget(
    runner: &dyn SshRunner,
    target: &Target,
    extra_options: &[String],
) -> io::Result<(Lookup, Vec<PathBuf>)> {
    let out = runner.run(&invocation(target, extra_options))?;
    if !out.success() {
        return Err(io::Error::other(format!(
            "ssh -G {}: {}",
            target.host,
            out.stderr.trim()
        )));
    }
    let lookup = parse(&out.stdout);
    let keygen = keygen_program();
    let mut changed = Vec::new();
    for file in lookup.files.iter().filter(|f| f.exists()) {
        if remove(&keygen, &lookup.name, file)? {
            changed.push(file.clone());
        }
    }
    Ok((lookup, changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::runner::SshOutput;
    use crate::ssh::runner::fake::FakeSsh;

    fn t(port: Option<u16>) -> Target {
        Target {
            user: Some("deploy".into()),
            host: "prod".into(),
            port,
        }
    }

    fn g(stdout: &str) -> SshOutput {
        SshOutput {
            code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invocation_asks_ssh_to_resolve_the_target() {
        let inv = invocation(&t(Some(2222)), &["UserKnownHostsFile=/k".into()]);
        assert_eq!(
            inv.args,
            [
                "-G",
                "-p",
                "2222",
                "-l",
                "deploy",
                "-o",
                "UserKnownHostsFile=/k",
                "--",
                "prod"
            ]
        );
        assert!(inv.capture);
    }

    #[test]
    fn parse_uses_the_port_form_off_22() {
        let l = parse(
            "user deploy\nhostname example.test\nport 2222\n\
             userknownhostsfile /h/.ssh/known_hosts /h/.ssh/known_hosts2\n",
        );
        assert_eq!(l.name, "[example.test]:2222");
        assert_eq!(
            l.files,
            [
                PathBuf::from("/h/.ssh/known_hosts"),
                PathBuf::from("/h/.ssh/known_hosts2")
            ]
        );
        assert_eq!(
            parse("hostname example.test\nport 22\n").name,
            "example.test"
        );
    }

    /// ssh records keys under a `HostKeyAlias` verbatim, port or not.
    #[test]
    fn parse_prefers_host_key_alias() {
        let l = parse("hostname example.test\nport 2222\nhostkeyalias prod-box\n");
        assert_eq!(l.name, "prod-box");
    }

    #[test]
    fn parse_skips_none() {
        assert!(
            parse("hostname h\nport 22\nuserknownhostsfile none\n")
                .files
                .is_empty()
        );
    }

    fn keygen() -> Option<PathBuf> {
        which::which("ssh-keygen").ok()
    }

    const LINE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOxSJm+vKgPtjF+3LXECms+G30LapzDZVnEL1zVmOdBP";

    #[test]
    fn remove_drops_only_the_named_entry() {
        let Some(keygen) = keygen() else { return };
        let tmp = tempfile::tempdir().unwrap();
        let kh = tmp.path().join("known_hosts");
        std::fs::write(&kh, format!("[prod]:2222 {LINE}\nother {LINE}\n")).unwrap();
        assert!(remove(&keygen, "[prod]:2222", &kh).unwrap());
        assert_eq!(
            std::fs::read_to_string(&kh).unwrap(),
            format!("other {LINE}\n")
        );
        assert!(
            !remove(&keygen, "[prod]:2222", &kh).unwrap(),
            "already gone"
        );
    }

    #[test]
    fn forget_touches_only_files_that_have_the_entry() {
        if keygen().is_none() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let has = tmp.path().join("known_hosts");
        let lacks = tmp.path().join("known_hosts2");
        let missing = tmp.path().join("known_hosts3");
        std::fs::write(&has, format!("prod {LINE}\n")).unwrap();
        std::fs::write(&lacks, format!("other {LINE}\n")).unwrap();
        let ssh = FakeSsh::new(vec![g(&format!(
            "hostname prod\nport 22\nuserknownhostsfile {} {} {}\n",
            has.display(),
            lacks.display(),
            missing.display()
        ))]);
        let (lookup, changed) = forget(&ssh, &t(None), &[]).unwrap();
        assert_eq!(lookup.name, "prod");
        assert_eq!(changed, std::slice::from_ref(&has));
        assert_eq!(std::fs::read_to_string(&has).unwrap(), "");
        assert_eq!(
            std::fs::read_to_string(&lacks).unwrap(),
            format!("other {LINE}\n")
        );
        assert!(!missing.exists());
    }
}
