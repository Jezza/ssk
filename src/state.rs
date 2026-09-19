//! `~/.ssh/ssk.toml`: what ssk knows that the key files can't tell it, namely
//! when an identity was created and where it has been installed.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fsx;

pub const FILE_NAME: &str = "ssk.toml";

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub identity: BTreeMap<String, IdentityState>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployments: Vec<Deployment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub port: u16,
    pub alias: String,
    /// RFC 3339 timestamp of the last successful install.
    pub installed: String,
}

impl Deployment {
    pub fn same_endpoint(&self, other: &Deployment) -> bool {
        self.host == other.host && self.user == other.user && self.port == other.port
    }

    /// `user@host:port` with the port only when it is not 22; IPv6 hosts in brackets.
    pub fn endpoint(&self) -> String {
        let mut e = String::new();
        if let Some(u) = &self.user {
            e.push_str(u);
            e.push('@');
        }
        if self.host.contains(':') {
            e.push('[');
            e.push_str(&self.host);
            e.push(']');
        } else {
            e.push_str(&self.host);
        }
        if self.port != 22 {
            e.push_str(&format!(":{}", self.port));
        }
        e
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("cannot read {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is not valid ssk state: {source}", .path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("cannot write {}: {source}", .path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot serialize state: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl State {
    pub fn path(ssh_dir: &Path) -> PathBuf {
        ssh_dir.join(FILE_NAME)
    }

    pub fn load(ssh_dir: &Path) -> Result<State, StateError> {
        let path = Self::path(ssh_dir);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
            Err(source) => return Err(StateError::Read { path, source }),
        };
        toml::from_str(&text).map_err(|source| StateError::Parse { path, source })
    }

    pub fn save(&self, ssh_dir: &Path) -> Result<(), StateError> {
        let path = Self::path(ssh_dir);
        let text = toml::to_string_pretty(self)?;
        fsx::write_private(&path, text.as_bytes())
            .map_err(|source| StateError::Write { path, source })
    }

    pub fn is_managed(&self, name: &str) -> bool {
        self.identity.contains_key(name)
    }

    pub fn record_created(&mut self, name: &str, when: String) {
        self.identity.entry(name.to_string()).or_default().created = Some(when);
    }

    /// Add a deployment, replacing any earlier record for the same host/user/port.
    pub fn record_deployment(&mut self, name: &str, dep: Deployment) {
        let entry = self.identity.entry(name.to_string()).or_default();
        entry.deployments.retain(|d| !d.same_endpoint(&dep));
        entry.deployments.push(dep);
    }

    pub fn deployments(&self, name: &str) -> &[Deployment] {
        self.identity
            .get(name)
            .map(|s| s.deployments.as_slice())
            .unwrap_or(&[])
    }

    pub fn remove_identity(&mut self, name: &str) -> Option<IdentityState> {
        self.identity.remove(name)
    }

    /// Move the entry for `old` to `new`. `false` when `old` had none.
    pub fn rename_identity(&mut self, old: &str, new: &str) -> bool {
        match self.identity.remove(old) {
            Some(entry) => {
                self.identity.insert(new.to_string(), entry);
                true
            }
            None => false,
        }
    }

    /// Drop deployments of `name` on `host:port`. `user == None` matches any user.
    /// Returns how many were removed.
    pub fn remove_deployments(
        &mut self,
        name: &str,
        host: &str,
        user: Option<&str>,
        port: u16,
    ) -> usize {
        let Some(entry) = self.identity.get_mut(name) else {
            return 0;
        };
        let before = entry.deployments.len();
        entry.deployments.retain(|d| {
            !(d.host == host && d.port == port && user.is_none_or(|u| d.user.as_deref() == Some(u)))
        });
        before - entry.deployments.len()
    }
}

/// Current time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now() -> String {
    jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(host: &str, user: Option<&str>, port: u16) -> Deployment {
        Deployment {
            host: host.into(),
            user: user.map(String::from),
            port,
            alias: host.into(),
            installed: "2026-09-18T10:20:31Z".into(),
        }
    }

    #[test]
    fn missing_file_loads_as_default() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(State::load(dir.path()).unwrap(), State::default());
    }

    #[test]
    fn round_trips_through_toml_with_expected_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = State::default();
        s.record_created("work", "2026-09-18T10:12:00Z".into());
        s.record_deployment("work", dep("10.0.0.5", Some("deploy"), 22));
        s.save(dir.path()).unwrap();

        let text = fs::read_to_string(State::path(dir.path())).unwrap();
        assert!(text.contains("[identity.work]"), "{text}");
        assert!(text.contains("[[identity.work.deployments]]"), "{text}");
        assert!(text.contains("host = \"10.0.0.5\""), "{text}");
        assert_eq!(
            crate::fsx::mode_of(&State::path(dir.path())).unwrap(),
            0o600
        );

        assert_eq!(State::load(dir.path()).unwrap(), s);
    }

    #[test]
    fn record_deployment_replaces_same_endpoint() {
        let mut s = State::default();
        s.record_deployment("work", dep("h", Some("a"), 22));
        s.record_deployment("work", dep("h", Some("a"), 22));
        s.record_deployment("work", dep("h", Some("b"), 22));
        s.record_deployment("work", dep("h", Some("a"), 2222));
        assert_eq!(s.deployments("work").len(), 3);
        assert!(s.is_managed("work"));
        assert!(!s.is_managed("other"));
        assert!(s.deployments("other").is_empty());
    }

    #[test]
    fn parse_error_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(State::path(dir.path()), "this is = not [toml").unwrap();
        let err = State::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("ssk.toml"), "{err}");
    }

    #[test]
    fn now_is_rfc3339_utc_seconds() {
        let n = now();
        assert_eq!(n.len(), 20, "{n}");
        assert!(n.ends_with('Z'));
        assert_eq!(&n[10..11], "T");
    }

    #[test]
    fn remove_and_rename_identity() {
        let mut s = State::default();
        s.record_created("work", "t".into());
        s.record_deployment("work", dep("h", None, 22));
        assert!(s.rename_identity("work", "job"));
        assert!(!s.is_managed("work") && s.is_managed("job"));
        assert_eq!(s.deployments("job").len(), 1);
        assert!(!s.rename_identity("nope", "x"));
        assert!(s.remove_identity("job").is_some());
        assert!(s.remove_identity("job").is_none());
        assert!(s.identity.is_empty());
    }

    #[test]
    fn remove_deployments_matches_host_port_and_optionally_user() {
        let mut s = State::default();
        s.record_deployment("work", dep("h", Some("a"), 22));
        s.record_deployment("work", dep("h", Some("b"), 22));
        s.record_deployment("work", dep("h", Some("a"), 2222));
        assert_eq!(s.remove_deployments("work", "h", Some("a"), 22), 1);
        assert_eq!(s.deployments("work").len(), 2);
        assert_eq!(
            s.remove_deployments("work", "h", None, 22),
            1,
            "no user matches any user"
        );
        assert_eq!(s.remove_deployments("work", "h", Some("zz"), 2222), 0);
        assert_eq!(s.remove_deployments("other", "h", None, 22), 0);
        assert_eq!(s.deployments("work").len(), 1);
    }

    #[test]
    fn endpoint_display() {
        assert_eq!(dep("h", Some("u"), 22).endpoint(), "u@h");
        assert_eq!(dep("h", None, 2222).endpoint(), "h:2222");
        assert_eq!(dep("::1", Some("u"), 22).endpoint(), "u@[::1]");
    }
}
