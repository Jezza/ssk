//! `~/.ssh/ssk.toml`: what ssk knows that the key files can't tell it —
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
}
