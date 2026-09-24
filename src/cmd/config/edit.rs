use std::process::Command;

use anyhow::{Context, ensure};

use crate::config_file;
use crate::settings::Settings;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Edit {}

pub fn handle(settings: &Settings, ui: &Ui, _args: &Edit) -> anyhow::Result<u8> {
    let path = super::config_path(settings)?;
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "vi".to_string());
    if settings.dry_run {
        ui.info(format!("would run: {editor} {}", path.display()));
        return Ok(0);
    }
    if !path.exists() {
        config_file::write_text(&path, config_file::TEMPLATE)?;
    }
    // $EDITOR may carry arguments ("code --wait"), so let sh split it; the path is $1.
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("ssk-config-edit")
        .arg(&path)
        .status()
        .with_context(|| format!("running {editor}"))?;
    ensure!(status.success(), "{editor} exited with {status}");
    match config_file::load(&path) {
        Ok(_) => {
            ui.success(format!("{} is valid", path.display()));
            Ok(0)
        }
        Err(e) => {
            ui.error(format!("{e}"));
            Ok(1)
        }
    }
}
