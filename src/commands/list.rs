use crate::{settings::Settings, ui::Ui};

pub fn run(_settings: &Settings, _ui: &Ui) -> anyhow::Result<u8> {
    anyhow::bail!("`ssk list` is not implemented yet")
}
