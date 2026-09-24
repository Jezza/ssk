use std::collections::BTreeMap;

use anyhow::bail;

use crate::config_file::ConfigError;
use crate::json;
use crate::settings::Settings;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Get {
    /// One key; all of them when omitted
    pub key: Option<String>,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Get) -> anyhow::Result<u8> {
    // Resolved only to fail the same way the other config subcommands do.
    super::config_path(settings)?;
    let rows = super::effective(settings);
    let Some(key) = &args.key else {
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
        return Ok(0);
    };
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
