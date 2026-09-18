//! `ssk config`: read and write the preferences file.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail, ensure};

use crate::cli::{ConfigAction, ConfigArgs};
use crate::config_file::{self, ConfigError};
use crate::json;
use crate::settings::{Settings, Source};
use crate::ui::Ui;

pub fn run(settings: &Settings, ui: &Ui, args: &ConfigArgs) -> anyhow::Result<u8> {
    let path = settings
        .config_path
        .clone()
        .context("cannot determine the config file path (no home directory)")?;
    match &args.action {
        ConfigAction::Path => {
            println!("{}", path.display());
            Ok(0)
        }
        ConfigAction::Get { key: None } => {
            let rows = effective(settings);
            if settings.json {
                let map: BTreeMap<&str, serde_json::Value> = rows
                    .iter()
                    .map(|(k, v, s)| (*k, serde_json::json!({"value": v, "source": s.as_str()})))
                    .collect();
                json::print(&map)?;
                return Ok(0);
            }
            for (k, v, s) in rows {
                ui.info(format!("{k:<18} {v:<32} ({})", s.as_str()));
            }
            Ok(0)
        }
        ConfigAction::Get { key: Some(key) } => {
            let rows = effective(settings);
            let Some((_, value, source)) = rows.into_iter().find(|(k, _, _)| k == key) else {
                bail!(ConfigError::UnknownKey(key.clone()));
            };
            if settings.json {
                json::print(&serde_json::json!({"value": value, "source": source.as_str()}))?;
            } else {
                println!("{value}");
            }
            Ok(0)
        }
        ConfigAction::Set { key, value } => {
            if settings.dry_run {
                ui.info(format!("would set {key} = {value} in {}", path.display()));
                return Ok(0);
            }
            config_file::set(&path, key, value)?;
            ui.success(format!("{key} = {value}  ({})", path.display()));
            Ok(0)
        }
        ConfigAction::Unset { key } => {
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
        ConfigAction::Edit => edit(&path, ui, settings.dry_run),
    }
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

fn edit(path: &Path, ui: &Ui, dry_run: bool) -> anyhow::Result<u8> {
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "vi".to_string());
    if dry_run {
        ui.info(format!("would run: {editor} {}", path.display()));
        return Ok(0);
    }
    if !path.exists() {
        config_file::write_text(path, config_file::TEMPLATE)?;
    }
    // $EDITOR may carry arguments ("code --wait"), so let sh split it; the path is $1.
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("ssk-config-edit")
        .arg(path)
        .status()
        .with_context(|| format!("running {editor}"))?;
    ensure!(status.success(), "{editor} exited with {status}");
    match config_file::load(path) {
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
