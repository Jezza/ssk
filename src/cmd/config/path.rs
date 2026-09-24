use crate::settings::Settings;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Path {}

pub fn handle(settings: &Settings, _ui: &Ui, _args: &Path) -> anyhow::Result<u8> {
    println!("{}", super::config_path(settings)?.display());
    Ok(0)
}
