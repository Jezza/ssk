//! `ssk add [IDENTITY...]`: load identities into ssh-agent.

use anyhow::bail;

use crate::cli::AddArgs;
use crate::settings::Settings;
use crate::ui::Ui;

pub fn run(_settings: &Settings, _ui: &Ui, _args: &AddArgs) -> anyhow::Result<u8> {
    bail!("`ssk add` is not implemented yet")
}
