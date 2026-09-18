use crate::{cli::DoctorArgs, settings::Settings, ui::Ui};

pub fn run(_settings: &Settings, _ui: &Ui, _args: &DoctorArgs) -> anyhow::Result<u8> {
    anyhow::bail!("`ssk doctor` is not implemented yet")
}
