//! `ssk agent list`: the keys ssh-agent holds, each matched to its identity by fingerprint.
//! Keys that are not ssk identities are listed too, named `-`.

use tabled::settings::Style;
use tabled::{Table, Tabled};

use crate::cmd::list::abbreviate_fingerprint;
use crate::identity::store::{self, Entry};
use crate::settings::Settings;
use crate::ssh::agent;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct List {}

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "FINGERPRINT")]
    fingerprint: String,
    #[tabled(rename = "COMMENT")]
    comment: String,
}

pub fn handle(settings: &Settings, ui: &Ui, _args: &List) -> anyhow::Result<u8> {
    let Some(listed) = agent::listing() else {
        anyhow::bail!(super::NO_AGENT);
    };
    if listed.is_empty() {
        ui.info("ssh-agent holds no keys");
        return Ok(0);
    }
    let identities: Vec<_> = store::scan(&settings.ssh_dir)?
        .into_iter()
        .filter_map(|e| match e {
            Entry::Identity(id) => Some(id),
            _ => None,
        })
        .collect();
    // The agent's own order is the order ssh offers the keys in, so it is kept.
    let rows: Vec<Row> = listed
        .into_iter()
        .map(|key| Row {
            name: identities
                .iter()
                .find(|id| id.fingerprint == key.fingerprint)
                .map_or_else(|| "-".to_string(), |id| id.name.clone()),
            fingerprint: abbreviate_fingerprint(&key.fingerprint),
            comment: key.comment,
        })
        .collect();
    let table = Table::new(&rows).with(Style::blank()).to_string();
    ui.info(table.trim_end());
    Ok(0)
}
