use crate::{cli::NewArgs, settings::Settings, ui::Ui};

pub fn run(_settings: &Settings, _ui: &Ui, _args: &NewArgs) -> anyhow::Result<u8> {
    anyhow::bail!("`ssk new` is not implemented yet")
}
