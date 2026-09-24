use crate::config_file;
use crate::settings::Settings;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Set {
    pub key: String,
    pub value: String,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Set) -> anyhow::Result<u8> {
    let path = super::config_path(settings)?;
    let Set { key, value } = args;
    if settings.dry_run {
        ui.info(format!("would set {key} = {value} in {}", path.display()));
        return Ok(0);
    }
    config_file::set(&path, key, value)?;
    ui.success(format!("{key} = {value}  ({})", path.display()));
    Ok(0)
}
