//! `ssk agent`: what ssh-agent holds of ours, and loading or unloading it.

use anyhow::bail;

use crate::identity::Identity;
use crate::identity::store::{self, Entry};
use crate::settings::Settings;
use crate::ssh::agent::AgentStatus;
use crate::ui::Ui;

mod list;
mod load;
mod unload;

#[derive(clap::Parser, Debug)]
pub struct Agent {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum Cmd {
    /// Load identities into ssh-agent
    Load(load::Load),
    /// Remove identities from ssh-agent
    Unload(unload::Unload),
    /// Show the keys ssh-agent holds and which identity each one is
    #[command(alias = "ls")]
    List(list::List),
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Agent) -> anyhow::Result<u8> {
    match &args.cmd {
        Cmd::Load(args) => load::handle(settings, ui, args),
        Cmd::Unload(args) => unload::handle(settings, ui, args),
        Cmd::List(args) => list::handle(settings, ui, args),
    }
}

/// The named identities, or every identity in the ssh dir when none are named.
fn identities(settings: &Settings, names: &[String]) -> anyhow::Result<Vec<Identity>> {
    if names.is_empty() {
        return Ok(store::scan(&settings.ssh_dir)?
            .into_iter()
            .filter_map(|e| match e {
                Entry::Identity(id) => Some(id),
                _ => None,
            })
            .collect());
    }
    Ok(names
        .iter()
        .map(|n| store::resolve(&settings.ssh_dir, n))
        .collect::<Result<_, _>>()?)
}

const NO_AGENT: &str = "no ssh-agent: SSH_AUTH_SOCK is unset or ssh-add cannot reach the agent";

fn require_agent(status: &AgentStatus) -> anyhow::Result<()> {
    if *status == AgentStatus::Unavailable {
        bail!(NO_AGENT);
    }
    Ok(())
}
