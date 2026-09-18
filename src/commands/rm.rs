//! `ssk rm <IDENTITY>`: delete an identity from this machine. Remote hosts are untouched;
//! `ssk revoke` is for those.

use std::fs;

use anyhow::Context;

use crate::cli::RmArgs;
use crate::identity::store;
use crate::identity::{Identity, name};
use crate::settings::Settings;
use crate::ssh::{agent, config};
use crate::state::State;
use crate::ui::Ui;

pub fn run(settings: &Settings, ui: &Ui, args: &RmArgs) -> anyhow::Result<u8> {
    name::validate(&args.identity)?;
    let dir = &settings.ssh_dir;
    let name = &args.identity;
    let mut st = State::load(dir)?;
    let what = store::remnants(dir, name, &st);
    if !what.any() {
        return Err(store::not_found(dir, name).into());
    }
    let private_path = dir.join(name);
    let public_path = dir.join(format!("{name}.pub"));
    let conf_path = config::conf_path(dir, name);
    // Parse if we can, for the agent check; an unparseable key is still removable.
    let identity = what
        .private
        .then(|| Identity::load(dir, name).ok())
        .flatten();

    ui.info(format!("removing identity '{name}':"));
    for (exists, path) in [
        (what.private, &private_path),
        (what.public, &public_path),
        (what.conf, &conf_path),
    ] {
        if exists {
            ui.info(format!("  {}", path.display()));
        }
    }
    if what.state {
        ui.info(format!("  entry in {}", State::path(dir).display()));
    }
    let deployments = st.deployments(name).to_vec();
    if !deployments.is_empty() {
        let hosts: Vec<String> = deployments.iter().map(|d| d.endpoint()).collect();
        ui.info(format!(
            "'{name}' is recorded on {} host{} ({}). They will keep accepting it.",
            hosts.len(),
            if hosts.len() == 1 { "" } else { "s" },
            hosts.join(", ")
        ));
        ui.info(format!(
            "Run `ssk revoke {name} --all` first if you want it gone from those hosts."
        ));
    }
    if settings.dry_run {
        ui.info("dry run: nothing removed");
        return Ok(0);
    }
    if !args.force && !ui.confirm(&format!("Remove '{name}'?"))? {
        return Ok(1);
    }

    // ssh-add -d needs the .pub, so this goes first; whether a failure matters is only
    // known once the files are gone (agent::still_loaded).
    let agent_failure = identity
        .as_ref()
        .filter(|id| agent::contains(&agent::status(), &id.fingerprint) == Some(true))
        .and_then(|id| agent::delete(&id.private_path, ui).err());
    for (exists, path) in [
        (what.private, &private_path),
        (what.public, &public_path),
        (what.conf, &conf_path),
    ] {
        if exists {
            fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        }
    }
    if what.state {
        st.remove_identity(name);
        st.save(dir)?;
    }
    if let Some(e) = agent_failure
        && let Some(id) = &identity
        && agent::still_loaded(&id.fingerprint)
    {
        ui.warn(format!("could not remove '{name}' from ssh-agent: {e:#}"));
    }
    ui.success(format!("removed identity {name}"));
    Ok(0)
}
