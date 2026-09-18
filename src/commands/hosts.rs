//! `ssk hosts`: host x identity deployment matrix.

use anyhow::bail;

use crate::settings::Settings;
use crate::ui::Ui;

pub fn run(_settings: &Settings, _ui: &Ui) -> anyhow::Result<u8> {
    bail!("`ssk hosts` is not implemented yet")
}
