//! ssh-agent, via the `ssh-add` binary. Absence of an agent is a normal state, not an error.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, ensure};

use crate::ui::Ui;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    /// No `SSH_AUTH_SOCK`, or `ssh-add` could not talk to the agent.
    Unavailable,
    /// SHA256 fingerprints currently loaded (possibly none).
    Loaded(Vec<String>),
}

/// One key the agent holds, from an `ssh-add -l` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub fingerprint: String,
    /// The key's comment, or the file it was loaded from when it has none.
    pub comment: String,
}

/// Parse `ssh-add -l` lines like `256 SHA256:... comment (ED25519)`.
pub fn parse_listing(stdout: &str) -> Vec<Listed> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace().skip(1);
            let fingerprint = words.next().filter(|f| f.starts_with("SHA256:"))?;
            let mut rest: Vec<&str> = words.collect();
            if rest
                .last()
                .is_some_and(|w| w.starts_with('(') && w.ends_with(')'))
            {
                rest.pop();
            }
            Some(Listed {
                fingerprint: fingerprint.to_string(),
                comment: rest.join(" "),
            })
        })
        .collect()
}

pub fn parse_list(stdout: &str) -> Vec<String> {
    parse_listing(stdout)
        .into_iter()
        .map(|l| l.fingerprint)
        .collect()
}

/// `SSK_SSH_ADD_BIN` if set (tests), else `ssh-add` from PATH.
pub fn program() -> PathBuf {
    std::env::var_os("SSK_SSH_ADD_BIN")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ssh-add"))
}

pub fn status() -> AgentStatus {
    status_with(std::env::var_os("SSH_AUTH_SOCK").as_deref())
}

pub fn status_with(auth_sock: Option<&OsStr>) -> AgentStatus {
    match list_output(auth_sock) {
        Some(stdout) => AgentStatus::Loaded(parse_list(&stdout)),
        None => AgentStatus::Unavailable,
    }
}

/// Every key the agent holds, comments included; `None` when there is no agent.
pub fn listing() -> Option<Vec<Listed>> {
    list_output(std::env::var_os("SSH_AUTH_SOCK").as_deref()).map(|s| parse_listing(&s))
}

/// `ssh-add -l` stdout, empty for an agent with no keys; `None` when there is no agent.
fn list_output(auth_sock: Option<&OsStr>) -> Option<String> {
    if auth_sock.is_none_or(|s| s.is_empty()) {
        return None;
    }
    match Command::new(program()).arg("-l").output() {
        Ok(out) if out.status.success() => Some(String::from_utf8_lossy(&out.stdout).into_owned()),
        // Exit 1 with "The agent has no identities." is a live, empty agent.
        Ok(out) if out.status.code() == Some(1) => Some(String::new()),
        _ => None,
    }
}

/// `Some(true)` loaded, `Some(false)` not loaded, `None` no agent to ask.
pub fn contains(status: &AgentStatus, fingerprint: &str) -> Option<bool> {
    match status {
        AgentStatus::Unavailable => None,
        AgentStatus::Loaded(fps) => Some(fps.iter().any(|f| f == fingerprint)),
    }
}

/// `ssh-add <key>` with inherited stdio, so its passphrase prompt reaches the user.
pub fn add(private_key: &Path, ui: &Ui) -> anyhow::Result<()> {
    let shown = private_key.display().to_string();
    ui.command("ssh-add", std::slice::from_ref(&shown));
    let status = Command::new(program()).arg(private_key).status()?;
    ensure!(status.success(), "ssh-add exited with {status}");
    Ok(())
}

/// `ssh-add -d <key>`. ssh-add reads `<key>.pub` to know which key to drop, so it never
/// prompts and its output can be captured: a failure carries ssh-add's own last line
/// (`Could not remove identity "...": agent refused operation`), and the caller decides
/// whether that is worth showing (see `still_loaded`).
pub fn delete(private_key: &Path, ui: &Ui) -> anyhow::Result<()> {
    let shown = private_key.display().to_string();
    ui.command("ssh-add", &["-d".to_string(), shown]);
    let out = Command::new(program())
        .arg("-d")
        .arg(private_key)
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    match stderr.lines().map(str::trim).rev().find(|l| !l.is_empty()) {
        Some(reason) => bail!("ssh-add -d: {reason}"),
        None => bail!("ssh-add -d exited with {}", out.status),
    }
}

/// Asked after a failed `delete`, once the key's files are gone: does the agent still list
/// the key? Only then is the failure worth a warning. gcr-ssh-agent (GNOME) lists every
/// `~/.ssh/*.pub` as loaded, refuses `ssh-add -d` for the ones it never actually holds, and
/// stops listing them as soon as the .pub is deleted; a real ssh-agent keeps listing a key
/// it still holds. No agent to ask counts as not loaded.
pub fn still_loaded(fingerprint: &str) -> bool {
    contains(&status(), fingerprint) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_extracts_sha256_fingerprints() {
        let out = "256 SHA256:abc/def+ghi= work@box (ED25519)\n3072 SHA256:zzz jz@box (RSA)\n";
        assert_eq!(parse_list(out), vec!["SHA256:abc/def+ghi=", "SHA256:zzz"]);
        assert!(parse_list("The agent has no identities.\n").is_empty());
        assert!(parse_list("").is_empty());
    }

    #[test]
    fn parse_listing_keeps_comments_and_drops_the_type() {
        let out =
            "256 SHA256:abc ops team key (ED25519)\n3072 SHA256:zzz /home/j/.ssh/bare (RSA)\n";
        assert_eq!(
            parse_listing(out),
            vec![
                Listed {
                    fingerprint: "SHA256:abc".into(),
                    comment: "ops team key".into()
                },
                Listed {
                    fingerprint: "SHA256:zzz".into(),
                    comment: "/home/j/.ssh/bare".into()
                },
            ]
        );
    }

    #[test]
    fn no_socket_means_unavailable_without_spawning() {
        assert_eq!(status_with(None), AgentStatus::Unavailable);
        assert_eq!(status_with(Some(OsStr::new(""))), AgentStatus::Unavailable);
    }

    #[test]
    fn contains_is_tristate() {
        assert_eq!(contains(&AgentStatus::Unavailable, "SHA256:a"), None);
        let loaded = AgentStatus::Loaded(vec!["SHA256:a".to_string()]);
        assert_eq!(contains(&loaded, "SHA256:a"), Some(true));
        assert_eq!(contains(&loaded, "SHA256:b"), Some(false));
    }
}
