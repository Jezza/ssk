use crate::{cli::ShowArgs, settings::Settings, ui::Ui};

pub fn run(_settings: &Settings, _ui: &Ui, _args: &ShowArgs) -> anyhow::Result<u8> {
    anyhow::bail!("`ssk show` is not implemented yet")
}
