//! `ssk agent load [IDENTITY...]`: load identities into ssh-agent via `ssh-add`.

use crate::settings::Settings;
use crate::ssh::agent;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Load {
    /// Identities to load; every identity when none are given
    #[arg(value_name = "IDENTITY")]
    pub identities: Vec<String>,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Load) -> anyhow::Result<u8> {
    let identities = super::identities(settings, &args.identities)?;
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
    super::require_agent(&status)?;
    let mut failed = 0;
    for id in &identities {
        if agent::contains(&status, &id.fingerprint) == Some(true) {
            ui.info(format!("{}: already in agent", id.name));
            continue;
        }
        match agent::add(&id.private_path, ui) {
            Ok(()) => ui.success(format!("{}: loaded", id.name)),
            Err(e) => {
                failed += 1;
                ui.error(format!("{}: {e:#}", id.name));
            }
        }
    }
    Ok(if failed == 0 { 0 } else { 1 })
}
