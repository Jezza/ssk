//! `ssk revoke <IDENTITY> [TARGET...]`: remove an identity's public key from hosts.

use anyhow::bail;

use crate::cli::RevokeArgs;
use crate::settings::Settings;
use crate::ui::Ui;

pub fn run(_settings: &Settings, _ui: &Ui, _args: &RevokeArgs) -> anyhow::Result<u8> {
    bail!("`ssk revoke` is not implemented yet")
}
