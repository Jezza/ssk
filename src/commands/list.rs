//! `ssk list`: one row per identity, plus rows for files that need attention.

use tabled::settings::Style;
use tabled::{Table, Tabled};

use crate::identity::store::{self, Entry};
use crate::settings::Settings;
use crate::ssh::agent::{self, AgentStatus};
use crate::state::State;
use crate::ui::Ui;

#[derive(Tabled, Debug, Clone, PartialEq, Eq)]
pub struct Row {
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "TYPE")]
    pub kind: String,
    #[tabled(rename = "FINGERPRINT")]
    pub fingerprint: String,
    #[tabled(rename = "PASS")]
    pub pass: String,
    #[tabled(rename = "AGENT")]
    pub agent: String,
    #[tabled(rename = "HOSTS")]
    pub hosts: String,
    #[tabled(rename = "COMMENT")]
    pub comment: String,
    #[tabled(rename = "")]
    pub flags: String,
}

/// `SHA256:` + first 12 hash characters + `…`. Full value via `ssk show`.
pub fn abbreviate_fingerprint(fp: &str) -> String {
    match fp.strip_prefix("SHA256:") {
        Some(hash) if hash.len() > 12 => format!("SHA256:{}…", &hash[..12]),
        _ => fp.to_string(),
    }
}

fn blank(name: &str, comment: &str, flags: &str) -> Row {
    Row {
        name: name.to_string(),
        kind: "?".to_string(),
        fingerprint: String::new(),
        pass: String::new(),
        agent: String::new(),
        hosts: String::new(),
        comment: comment.to_string(),
        flags: flags.to_string(),
    }
}

/// Managed identities (known to ssk.toml) first, then unmanaged, each group by name.
pub fn build_rows(entries: &[Entry], state: &State, agent: &AgentStatus) -> Vec<Row> {
    let mut rows: Vec<(bool, Row)> = Vec::new();
    for entry in entries {
        match entry {
            Entry::Identity(id) => {
                let hosts = state.deployments(&id.name).len();
                let row = Row {
                    name: id.name.clone(),
                    kind: id.type_label(),
                    fingerprint: abbreviate_fingerprint(&id.fingerprint),
                    pass: if id.encrypted { "yes" } else { "no" }.to_string(),
                    agent: match agent::contains(agent, &id.fingerprint) {
                        Some(true) => "yes",
                        Some(false) => "-",
                        None => "n/a",
                    }
                    .to_string(),
                    hosts: if hosts == 0 {
                        "-".to_string()
                    } else {
                        hosts.to_string()
                    },
                    comment: id.comment.clone(),
                    flags: if id.public_path.is_none() {
                        "⚠ no .pub".to_string()
                    } else {
                        String::new()
                    },
                };
                rows.push((state.is_managed(&id.name), row));
            }
            Entry::Broken { name, .. } => rows.push((false, blank(name, "", "⚠ unreadable"))),
            Entry::OrphanPublic { name, .. } => {
                rows.push((false, blank(name, "(no private key)", "⚠")))
            }
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
    rows.into_iter().map(|(_, row)| row).collect()
}

pub fn run(settings: &Settings, ui: &Ui) -> anyhow::Result<u8> {
    let entries = store::scan(&settings.ssh_dir)?;
    let state = State::load(&settings.ssh_dir)?;
    let agent = agent::status();
    let rows = build_rows(&entries, &state, &agent);
    if rows.is_empty() {
        ui.info(format!(
            "no identities in {}. Create one with `ssk new <name>`.",
            settings.ssh_dir.display()
        ));
        return Ok(0);
    }
    let flagged = rows.iter().any(|r| !r.flags.is_empty());
    let table = Table::new(&rows).with(Style::blank()).to_string();
    ui.info(table.trim_end());
    if flagged {
        ui.hint("ssk doctor   (some entries are flagged)");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::path::PathBuf;

    fn ident(name: &str, fp: &str, encrypted: bool, has_pub: bool) -> Entry {
        Entry::Identity(Identity {
            name: name.into(),
            private_path: PathBuf::from(format!("/s/{name}")),
            public_path: has_pub.then(|| PathBuf::from(format!("/s/{name}.pub"))),
            algorithm: "ed25519".into(),
            bits: None,
            fingerprint: fp.into(),
            encrypted,
            comment: format!("{name}@box"),
        })
    }

    #[test]
    fn abbreviates_sha256_only() {
        assert_eq!(
            abbreviate_fingerprint("SHA256:abcdefghijklmnopqrstuvwxyz"),
            "SHA256:abcdefghijkl…"
        );
        assert_eq!(abbreviate_fingerprint("SHA256:short"), "SHA256:short");
        assert_eq!(abbreviate_fingerprint("MD5:aa:bb"), "MD5:aa:bb");
    }

    #[test]
    fn rows_are_managed_first_then_alphabetical_with_tristate_agent() {
        let entries = vec![
            ident("zeta", "SHA256:z", false, true),
            ident("alpha", "SHA256:a", true, true),
            ident("mid", "SHA256:m", false, false),
        ];
        let mut state = State::default();
        state.record_created("zeta", "t".into());
        let agent = AgentStatus::Loaded(vec!["SHA256:a".into()]);
        let rows = build_rows(&entries, &state, &agent);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["zeta", "alpha", "mid"]);
        assert_eq!(rows[1].pass, "yes");
        assert_eq!(rows[1].agent, "yes");
        assert_eq!(rows[0].agent, "-");
        assert_eq!(rows[0].hosts, "-");
        assert!(rows[2].flags.contains("no .pub"));

        let rows = build_rows(&entries, &state, &AgentStatus::Unavailable);
        assert_eq!(rows[0].agent, "n/a");
    }

    #[test]
    fn broken_and_orphan_rows_are_flagged() {
        let entries = vec![
            Entry::Broken {
                name: "old".into(),
                path: "/s/old".into(),
                error: crate::identity::IdentityError::LegacyPem {
                    path: "/s/old".into(),
                },
            },
            Entry::OrphanPublic {
                name: "lost".into(),
                path: "/s/lost.pub".into(),
            },
        ];
        // both unmanaged, so alphabetical: "lost" (orphan) before "old" (broken)
        let rows = build_rows(&entries, &State::default(), &AgentStatus::Unavailable);
        assert_eq!(rows[0].name, "lost");
        assert_eq!(rows[0].kind, "?");
        assert_eq!(rows[0].comment, "(no private key)");
        assert!(rows[0].flags.starts_with('⚠'));
        assert_eq!(rows[1].name, "old");
        assert!(rows[1].flags.contains("unreadable"));
    }
}
