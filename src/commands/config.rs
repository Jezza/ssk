//! `ssk config <ACTION>`: read or write ~/.config/ssk/config.toml.

use anyhow::bail;

use crate::cli::ConfigArgs;
use crate::settings::Settings;
use crate::ui::Ui;

pub fn run(_settings: &Settings, _ui: &Ui, _args: &ConfigArgs) -> anyhow::Result<u8> {
    bail!("`ssk config` is not implemented yet")
}
