use crate::{cli::CopyArgs, settings::Settings, ui::Ui};

pub fn run(_settings: &Settings, _ui: &Ui, _args: &CopyArgs) -> anyhow::Result<u8> {
    anyhow::bail!("`ssk copy` is not implemented yet")
}
