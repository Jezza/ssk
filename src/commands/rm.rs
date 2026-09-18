//! `ssk rm <IDENTITY>`: delete an identity from this machine.

use anyhow::bail;

use crate::cli::RmArgs;
use crate::settings::Settings;
use crate::ui::Ui;

pub fn run(_settings: &Settings, _ui: &Ui, _args: &RmArgs) -> anyhow::Result<u8> {
    bail!("`ssk rm` is not implemented yet")
}
