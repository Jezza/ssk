//! Serializable views for `--json`. The shapes are documented in the lifecycle spec;
//! change them there first.

use std::path::PathBuf;

use serde::Serialize;

use crate::commands::doctor::{Finding, Severity};
use crate::identity::Identity;
use crate::identity::store::Entry;
use crate::ssh::agent::{self, AgentStatus};
use crate::state::{Deployment, State};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityFields {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub bits: Option<u32>,
    pub fingerprint: String,
    pub encrypted: bool,
    /// `None` when there is no agent to ask.
    pub in_agent: Option<bool>,
    pub hosts: usize,
    pub comment: String,
    pub managed: bool,
    pub private_path: PathBuf,
    pub public_path: Option<PathBuf>,
}

impl IdentityFields {
    pub fn new(id: &Identity, state: &State, agent: &AgentStatus) -> IdentityFields {
        IdentityFields {
            name: id.name.clone(),
            kind: id.algorithm.clone(),
            bits: id.bits,
            fingerprint: id.fingerprint.clone(),
            encrypted: id.encrypted,
            in_agent: agent::contains(agent, &id.fingerprint),
            hosts: state.deployments(&id.name).len(),
            comment: id.comment.clone(),
            managed: state.is_managed(&id.name),
            private_path: id.private_path.clone(),
            public_path: id.public_path.clone(),
        }
    }
}

/// `ok` or `no-pub` for a loaded identity.
pub fn status_of(id: &Identity) -> &'static str {
    if id.public_path.is_some() {
        "ok"
    } else {
        "no-pub"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum IdentityJson {
    Ok(IdentityFields),
    NoPub(IdentityFields),
    Unreadable {
        name: String,
        error: String,
        private_path: PathBuf,
    },
    OrphanPub {
        name: String,
        public_path: PathBuf,
    },
}

impl IdentityJson {
    pub fn from_entry(entry: &Entry, state: &State, agent: &AgentStatus) -> IdentityJson {
        match entry {
            Entry::Identity(id) => {
                let fields = IdentityFields::new(id, state, agent);
                if id.public_path.is_some() {
                    IdentityJson::Ok(fields)
                } else {
                    IdentityJson::NoPub(fields)
                }
            }
            Entry::Broken { name, path, error } => IdentityJson::Unreadable {
                name: name.clone(),
                error: error.to_string(),
                private_path: path.clone(),
            },
            Entry::OrphanPublic { name, path } => IdentityJson::OrphanPub {
                name: name.clone(),
                public_path: path.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShowJson {
    pub status: &'static str,
    #[serde(flatten)]
    pub identity: IdentityFields,
    pub private_mode: String,
    pub public_mode: Option<String>,
    pub created: Option<String>,
    pub deployments: Vec<DeploymentJson>,
    pub ssh_config: Option<PathBuf>,
    pub public_key: Option<String>,
}

/// Like `state::Deployment`, but without `skip_serializing_if` on `user`: in the
/// JSON document every optional field stays present as `null`, unlike the TOML file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeploymentJson {
    pub host: String,
    pub user: Option<String>,
    pub port: u16,
    pub alias: String,
    pub installed: String,
}

impl From<&Deployment> for DeploymentJson {
    fn from(d: &Deployment) -> Self {
        DeploymentJson {
            host: d.host.clone(),
            user: d.user.clone(),
            port: d.port,
            alias: d.alias.clone(),
            installed: d.installed.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingJson {
    pub id: &'static str,
    pub severity: &'static str,
    pub path: PathBuf,
    pub message: String,
    pub fixable: bool,
}

impl From<&Finding> for FindingJson {
    fn from(f: &Finding) -> Self {
        FindingJson {
            id: f.id,
            severity: match f.severity {
                Severity::Warn => "warn",
                Severity::Info => "info",
            },
            path: f.path.clone(),
            message: f.message.clone(),
            fixable: f.fix.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorJson {
    pub findings: Vec<FindingJson>,
    /// Fixes applied this run; 0 unless `--fix`.
    pub applied: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostJson {
    pub host: String,
    pub user: Option<String>,
    pub port: u16,
    pub alias: String,
    pub identities: Vec<HostIdentityJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostIdentityJson {
    pub name: String,
    pub installed: String,
}

/// Pretty-printed document on stdout. Bypasses `Ui` on purpose: the JSON *is* the
/// output and must appear even under `--quiet`.
pub fn print<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityError;
    use std::path::PathBuf;

    fn ident(name: &str, has_pub: bool) -> Identity {
        Identity {
            name: name.into(),
            private_path: PathBuf::from(format!("/s/{name}")),
            public_path: has_pub.then(|| PathBuf::from(format!("/s/{name}.pub"))),
            algorithm: "ed25519".into(),
            bits: None,
            fingerprint: "SHA256:abc".into(),
            encrypted: true,
            comment: "c".into(),
        }
    }

    #[test]
    fn identity_entries_map_to_documented_shapes() {
        let mut state = State::default();
        state.record_created("work", "t".into());
        let agent = AgentStatus::Loaded(vec!["SHA256:abc".into()]);
        let v = serde_json::to_value(IdentityJson::from_entry(
            &Entry::Identity(ident("work", true)),
            &state,
            &agent,
        ))
        .unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["type"], "ed25519");
        assert_eq!(v["bits"], serde_json::Value::Null);
        assert_eq!(v["in_agent"], true);
        assert_eq!(v["managed"], true);
        assert_eq!(v["hosts"], 0);
        assert_eq!(v["public_path"], "/s/work.pub");

        let v = serde_json::to_value(IdentityJson::from_entry(
            &Entry::Identity(ident("lonely", false)),
            &State::default(),
            &AgentStatus::Unavailable,
        ))
        .unwrap();
        assert_eq!(v["status"], "no-pub");
        assert_eq!(v["in_agent"], serde_json::Value::Null);
        assert_eq!(v["managed"], false);

        let v = serde_json::to_value(IdentityJson::from_entry(
            &Entry::Broken {
                name: "old".into(),
                path: "/s/old".into(),
                error: IdentityError::LegacyPem {
                    path: "/s/old".into(),
                },
            },
            &State::default(),
            &AgentStatus::Unavailable,
        ))
        .unwrap();
        assert_eq!(v["status"], "unreadable");
        assert!(v["error"].as_str().unwrap().contains("legacy PEM"));
        assert_eq!(v["private_path"], "/s/old");

        let v = serde_json::to_value(IdentityJson::from_entry(
            &Entry::OrphanPublic {
                name: "lost".into(),
                path: "/s/lost.pub".into(),
            },
            &State::default(),
            &AgentStatus::Unavailable,
        ))
        .unwrap();
        assert_eq!(v["status"], "orphan-pub");
        assert_eq!(v["public_path"], "/s/lost.pub");
    }

    #[test]
    fn doctor_and_host_shapes() {
        let f = crate::commands::doctor::Finding {
            id: "key-perms",
            severity: crate::commands::doctor::Severity::Warn,
            path: "/s/work".into(),
            message: "m".into(),
            fix: Some(crate::commands::doctor::Fix::Chmod(0o600)),
        };
        let v = serde_json::to_value(DoctorJson {
            findings: vec![FindingJson::from(&f)],
            applied: 1,
        })
        .unwrap();
        assert_eq!(v["findings"][0]["severity"], "warn");
        assert_eq!(v["findings"][0]["fixable"], true);
        assert_eq!(v["applied"], 1);

        let h = HostJson {
            host: "h".into(),
            user: None,
            port: 22,
            alias: "h".into(),
            identities: vec![HostIdentityJson {
                name: "work".into(),
                installed: "t".into(),
            }],
        };
        let v = serde_json::to_value(h).unwrap();
        assert_eq!(v["user"], serde_json::Value::Null);
        assert_eq!(v["identities"][0]["name"], "work");
    }

    #[test]
    fn deployment_json_keeps_null_user() {
        let dep = Deployment {
            host: "a.test".into(),
            user: None,
            port: 2222,
            alias: "a.test".into(),
            installed: "t".into(),
        };
        let v = serde_json::to_value(DeploymentJson::from(&dep)).unwrap();
        assert_eq!(v["user"], serde_json::Value::Null);
        assert_eq!(v.as_object().unwrap().len(), 5);
    }
}
