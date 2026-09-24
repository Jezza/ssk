//! `ssk add [IDENTITY...]`: load identities into ssh-agent via `ssh-add`.

use anyhow::bail;

use crate::identity::Identity;
use crate::identity::store::{self, Entry};
use crate::settings::Settings;
use crate::ssh::agent::{self, AgentStatus};
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Add {
    /// Identities to load; every identity when none are given
    #[arg(value_name = "IDENTITY")]
    pub identities: Vec<String>,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Add) -> anyhow::Result<u8> {
    let identities: Vec<Identity> = if args.identities.is_empty() {
        store::scan(&settings.ssh_dir)?
            .into_iter()
            .filter_map(|e| match e {
                Entry::Identity(id) => Some(id),
                _ => None,
            })
            .collect()
    } else {
        args.identities
            .iter()
            .map(|n| store::resolve(&settings.ssh_dir, n))
            .collect::<Result<_, _>>()?
    };
    if identities.is_empty() {
        ui.info(format!(
            "no identities in {}. Create one with `ssk new <name>`.",
            settings.ssh_dir.display()
        ));
        return Ok(0);
    }
    if settings.dry_run {
        for id in &identities {
            ui.info(format!("would run: ssh-add {}", id.private_path.display()));
        }
        return Ok(0);
    }
    let status = agent::status();
    if status == AgentStatus::Unavailable {
        bail!("no ssh-agent to add to: SSH_AUTH_SOCK is unset or ssh-add cannot reach the agent");
    }
    let mut failed = 0;
    for id in &identities {
        if agent::contains(&status, &id.fingerprint) == Some(true) {
            ui.info(format!("{}: already in agent", id.name));
            continue;
        }
        match agent::add(&id.private_path, ui) {
            Ok(()) => ui.success(format!("{}: added", id.name)),
            Err(e) => {
                failed += 1;
                ui.error(format!("{}: {e:#}", id.name));
            }
        }
    }
    Ok(if failed == 0 { 0 } else { 1 })
}
