//! `ssk rotate <IDENTITY>`: replace an identity's key: install the new key everywhere, revoke the old one, swap.

use anyhow::bail;

use crate::cli::RotateArgs;
use crate::settings::Settings;
use crate::ui::Ui;

pub fn run(_settings: &Settings, _ui: &Ui, _args: &RotateArgs) -> anyhow::Result<u8> {
    bail!("`ssk rotate` is not implemented yet")
}
