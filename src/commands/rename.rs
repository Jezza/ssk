//! `ssk rename <OLD> <NEW>`: rename an identity; state and generated ssh config follow.

use anyhow::bail;

use crate::cli::RenameArgs;
use crate::settings::Settings;
use crate::ui::Ui;

pub fn run(_settings: &Settings, _ui: &Ui, _args: &RenameArgs) -> anyhow::Result<u8> {
    bail!("`ssk rename` is not implemented yet")
}
