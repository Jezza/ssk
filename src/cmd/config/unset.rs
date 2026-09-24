use crate::config_file;
use crate::settings::Settings;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Unset {
    pub key: String,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Unset) -> anyhow::Result<u8> {
    let path = super::config_path(settings)?;
    let key = &args.key;
    if settings.dry_run {
        ui.info(format!("would remove {key} from {}", path.display()));
        return Ok(0);
    }
    if config_file::unset(&path, key)? {
        ui.success(format!("removed {key} from {}", path.display()));
    } else {
        ui.info(format!("{key} is not set in {}", path.display()));
    }
    Ok(0)
}
