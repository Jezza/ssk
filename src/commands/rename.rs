//! `ssk rename <OLD> <NEW>`: move the key pair; ssk.toml and ssk.d follow. The user's
//! own ~/.ssh/config is never edited, only reported.

use std::fs;

use anyhow::{Context, bail};

use crate::cli::RenameArgs;
use crate::identity::{name, store};
use crate::settings::Settings;
use crate::ssh::config;
use crate::state::State;
use crate::ui::Ui;

pub fn run(settings: &Settings, ui: &Ui, args: &RenameArgs) -> anyhow::Result<u8> {
    name::validate(&args.old)?;
    name::validate(&args.new)?;
    let dir = &settings.ssh_dir;
    let (old, new) = (&args.old, &args.new);
    let old_priv = dir.join(old);
    if !old_priv.is_file() {
        return Err(store::not_found(dir, old).into());
    }
    let old_pub = dir.join(format!("{old}.pub"));
    let new_priv = dir.join(new);
    let new_pub = dir.join(format!("{new}.pub"));
    if new_priv.exists() || new_pub.exists() {
        bail!(
            "identity '{new}' already exists at {}; remove it first",
            new_priv.display()
        );
    }
    let mut st = State::load(dir)?;
    let had_conf = config::conf_path(dir, old).is_file();
    let mentions = config::user_config_mentions(dir, old)?;

    ui.info(format!(
        "rename {} -> {}",
        old_priv.display(),
        new_priv.display()
    ));
    if old_pub.is_file() {
        ui.info(format!(
            "rename {} -> {}",
            old_pub.display(),
            new_pub.display()
        ));
    }
    if st.is_managed(old) {
        ui.info(format!(
            "move entry '{old}' -> '{new}' in {}",
            State::path(dir).display()
        ));
    }
    if had_conf {
        ui.info(format!(
            "replace {} with {}",
            config::conf_path(dir, old).display(),
            config::conf_path(dir, new).display()
        ));
    }
    if settings.dry_run {
        ui.info("dry run: nothing renamed");
        return Ok(0);
    }

    fs::rename(&old_priv, &new_priv).with_context(|| format!("renaming {}", old_priv.display()))?;
    if old_pub.is_file()
        && let Err(e) = fs::rename(&old_pub, &new_pub)
    {
        let _ = fs::rename(&new_priv, &old_priv);
        return Err(e).with_context(|| {
            format!(
                "renaming {}; the private key was moved back",
                old_pub.display()
            )
        });
    }
    if st.rename_identity(old, new) {
        st.save(dir)?;
    }
    if had_conf {
        config::remove_conf(dir, old)?;
        config::sync_conf(dir, new, st.deployments(new))?;
    }
    ui.success(format!("renamed identity {old} -> {new}"));
    if !mentions.is_empty() {
        let lines: Vec<String> = mentions.iter().map(|(n, _)| n.to_string()).collect();
        ui.warn(format!(
            "{} still mentions '{old}' on line{} {}; ssk never edits that file, so update it yourself:",
            dir.join("config").display(),
            if lines.len() == 1 { "" } else { "s" },
            lines.join(", ")
        ));
        for (n, line) in &mentions {
            ui.warn(format!("  {n}: {}", line.trim()));
        }
    }
    Ok(0)
}
