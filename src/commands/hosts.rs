//! `ssk hosts`: every endpoint ssk has installed something on, and which identities.
//! Read-only over ssk.toml; nothing is probed.

use std::collections::{BTreeMap, BTreeSet};

use tabled::builder::Builder;
use tabled::settings::Style;

use crate::json::{self, HostIdentityJson, HostJson};
use crate::settings::Settings;
use crate::state::{Deployment, State};
use crate::ui::Ui;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRow {
    pub host: String,
    pub user: Option<String>,
    pub port: u16,
    pub aliases: BTreeSet<String>,
    /// identity name -> installed timestamp
    pub identities: BTreeMap<String, String>,
}

impl HostRow {
    pub fn endpoint(&self) -> String {
        Deployment {
            host: self.host.clone(),
            user: self.user.clone(),
            port: self.port,
            alias: String::new(),
            installed: String::new(),
        }
        .endpoint()
    }
}

/// One row per (host, port, user), sorted that way.
pub fn collect(state: &State) -> Vec<HostRow> {
    let mut map: BTreeMap<(String, u16, Option<String>), HostRow> = BTreeMap::new();
    for (name, entry) in &state.identity {
        for d in &entry.deployments {
            let row = map
                .entry((d.host.clone(), d.port, d.user.clone()))
                .or_insert_with(|| HostRow {
                    host: d.host.clone(),
                    user: d.user.clone(),
                    port: d.port,
                    aliases: BTreeSet::new(),
                    identities: BTreeMap::new(),
                });
            row.aliases.insert(d.alias.clone());
            row.identities.insert(name.clone(), d.installed.clone());
        }
    }
    map.into_values().collect()
}

/// Identities present in any row, alphabetical: the table's columns.
pub fn columns(rows: &[HostRow]) -> Vec<String> {
    rows.iter()
        .flat_map(|r| r.identities.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn render(rows: &[HostRow]) -> String {
    let cols = columns(rows);
    let mut b = Builder::default();
    let mut header = vec!["HOST".to_string(), "ALIAS".to_string()];
    header.extend(cols.iter().cloned());
    b.push_record(header);
    for r in rows {
        let aliases: Vec<&str> = r
            .aliases
            .iter()
            .filter(|a| **a != r.host)
            .map(String::as_str)
            .collect();
        let alias = if aliases.is_empty() {
            "-".to_string()
        } else {
            aliases.join(",")
        };
        let mut record = vec![r.endpoint(), alias];
        record.extend(cols.iter().map(|c| {
            if r.identities.contains_key(c) {
                "✓"
            } else {
                "-"
            }
            .to_string()
        }));
        b.push_record(record);
    }
    let mut table = b.build();
    table.with(Style::blank());
    table.to_string()
}

pub fn to_json(rows: &[HostRow]) -> Vec<HostJson> {
    rows.iter()
        .map(|r| HostJson {
            host: r.host.clone(),
            user: r.user.clone(),
            port: r.port,
            alias: r.aliases.iter().cloned().collect::<Vec<_>>().join(","),
            identities: r
                .identities
                .iter()
                .map(|(name, installed)| HostIdentityJson {
                    name: name.clone(),
                    installed: installed.clone(),
                })
                .collect(),
        })
        .collect()
}

pub fn run(settings: &Settings, ui: &Ui) -> anyhow::Result<u8> {
    let state = State::load(&settings.ssh_dir)?;
    let rows = collect(&state);
    if settings.json {
        json::print(&to_json(&rows))?;
        return Ok(0);
    }
    if rows.is_empty() {
        ui.info("no deployments recorded. `ssk copy <identity> user@host` records one.");
        return Ok(0);
    }
    ui.info(render(&rows).trim_end());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Deployment;

    fn dep(host: &str, user: Option<&str>, port: u16, alias: &str) -> Deployment {
        Deployment {
            host: host.into(),
            user: user.map(String::from),
            port,
            alias: alias.into(),
            installed: format!("t-{alias}"),
        }
    }

    fn state() -> State {
        let mut s = State::default();
        s.record_deployment("work", dep("b.test", None, 22, "b.test"));
        s.record_deployment("work", dep("a.test", Some("deploy"), 2222, "prod"));
        s.record_deployment("github", dep("b.test", None, 22, "gh"));
        s.record_deployment("zeta", dep("a.test", Some("deploy"), 22, "a.test"));
        s
    }

    #[test]
    fn collect_groups_by_endpoint_and_sorts() {
        let rows = collect(&state());
        let endpoints: Vec<String> = rows.iter().map(|r| r.endpoint()).collect();
        assert_eq!(
            endpoints,
            vec!["deploy@a.test", "deploy@a.test:2222", "b.test"]
        );
        assert_eq!(rows[1].identities.keys().collect::<Vec<_>>(), vec!["work"]);
        assert_eq!(
            rows[2].identities.keys().collect::<Vec<_>>(),
            vec!["github", "work"]
        );
        assert_eq!(
            rows[2].aliases.iter().collect::<Vec<_>>(),
            vec!["b.test", "gh"]
        );
        assert_eq!(columns(&rows), vec!["github", "work", "zeta"]);
    }

    #[test]
    fn render_marks_cells_and_hides_trivial_aliases() {
        let text = render(&collect(&state()));
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].contains("HOST") && lines[0].contains("ALIAS") && lines[0].contains("github"),
            "{text}"
        );
        let b = lines
            .iter()
            .find(|l| l.trim_start().starts_with("b.test"))
            .unwrap();
        assert!(b.contains("gh") && !b.contains("b.test,"), "{b}");
        assert!(b.matches('✓').count() == 2, "{b}");
        let a = lines
            .iter()
            .find(|l| l.contains("deploy@a.test:2222"))
            .unwrap();
        assert!(
            a.contains("prod") && a.matches('✓').count() == 1 && a.contains('-'),
            "{a}"
        );
    }

    #[test]
    fn json_view() {
        let v = serde_json::to_value(to_json(&collect(&state()))).unwrap();
        assert_eq!(v[2]["host"], "b.test");
        assert_eq!(v[2]["alias"], "b.test,gh");
        assert_eq!(v[2]["identities"][0]["name"], "github");
        assert_eq!(v[2]["identities"][0]["installed"], "t-gh");
        assert_eq!(v[0]["user"], "deploy");
        assert_eq!(v[1]["port"], 2222);
    }
}
