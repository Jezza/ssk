//! `ssk config`: read and write the preferences file.

use std::path::PathBuf;

use anyhow::Context;

use crate::settings::{Settings, Source};
use crate::ui::Ui;

mod edit;
mod get;
mod path;
mod set;
mod unset;

#[derive(clap::Parser, Debug)]
pub struct Config {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum Cmd {
    /// Print the config file path
    Path(path::Path),
    /// Show effective values and where each comes from
    Get(get::Get),
    /// Validate and write a value to the config file
    Set(set::Set),
    /// Remove a key from the config file
    Unset(unset::Unset),
    /// Open the config file in $VISUAL, $EDITOR or vi
    Edit(edit::Edit),
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Config) -> anyhow::Result<u8> {
    match &args.cmd {
        Cmd::Path(args) => path::handle(settings, ui, args),
        Cmd::Get(args) => get::handle(settings, ui, args),
        Cmd::Set(args) => set::handle(settings, ui, args),
        Cmd::Unset(args) => unset::handle(settings, ui, args),
        Cmd::Edit(args) => edit::handle(settings, ui, args),
    }
}

fn config_path(settings: &Settings) -> anyhow::Result<PathBuf> {
    settings
        .config_path
        .clone()
        .context("cannot determine the config file path (no home directory)")
}

/// Every key with its effective value (as the user would type it) and source.
pub fn effective(s: &Settings) -> Vec<(&'static str, String, Source)> {
    let src = |k: &str| s.sources.get(k).copied().unwrap_or(Source::Default);
    vec![
        ("ssh_dir", s.ssh_dir.display().to_string(), src("ssh_dir")),
        (
            "default_type",
            s.default_type.as_str().to_string(),
            src("default_type"),
        ),
        ("rsa_bits", s.rsa_bits.to_string(), src("rsa_bits")),
        ("comment", s.comment_template.clone(), src("comment")),
        (
            "add_to_agent",
            s.add_to_agent.to_string(),
            src("add_to_agent"),
        ),
        (
            "write_ssh_config",
            s.write_ssh_config.to_string(),
            src("write_ssh_config"),
        ),
    ]
}
