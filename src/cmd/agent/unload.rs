//! `ssk agent unload [IDENTITY...]`: remove identities from ssh-agent via `ssh-add -d`.
//! Keys in the agent that are not ssk identities are left alone.

use crate::settings::Settings;
use crate::ssh::agent;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Unload {
    /// Identities to unload; every identity the agent holds when none are given
    #[arg(value_name = "IDENTITY")]
    pub identities: Vec<String>,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Unload) -> anyhow::Result<u8> {
    let named = !args.identities.is_empty();
    let identities = super::identities(settings, &args.identities)?;
    let status = agent::status();
    // Dry run still asks the agent: which keys would go is the whole question.
    super::require_agent(&status)?;
    let loaded: Vec<_> = identities
        .iter()
        .filter(|id| {
            let held = agent::contains(&status, &id.fingerprint) == Some(true);
            if !held && named {
                ui.info(format!("{}: not in agent", id.name));
            }
            held
        })
        .collect();
    if loaded.is_empty() {
        if !named {
            ui.info("ssh-agent holds no ssk identities");
        }
        return Ok(0);
    }
    if settings.dry_run {
        for id in &loaded {
            ui.info(format!(
                "would run: ssh-add -d {}",
                id.private_path.display()
            ));
        }
        return Ok(0);
    }
    let mut failed = 0;
    for id in loaded {
        match agent::delete(&id.private_path, ui) {
            Ok(()) => ui.success(format!("{}: unloaded", id.name)),
            Err(e) => {
                failed += 1;
                ui.error(format!("{}: {e:#}", id.name));
            }
        }
    }
    Ok(if failed == 0 { 0 } else { 1 })
}
