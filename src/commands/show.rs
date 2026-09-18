//! `ssk show <IDENTITY>`: everything ssk knows about one identity.

use std::fmt::Write as _;
use std::path::Path;

use crate::cli::ShowArgs;
use crate::fsx;
use crate::identity::Identity;
use crate::identity::store;
use crate::settings::Settings;
use crate::ssh::agent::{self, AgentStatus};
use crate::state::{Deployment, State};
use crate::ui::Ui;

pub fn run(settings: &Settings, ui: &Ui, args: &ShowArgs) -> anyhow::Result<u8> {
    let id = store::resolve(&settings.ssh_dir, &args.identity)?;
    if args.pub_only {
        println!("{}", id.public_key_line()?);
        return Ok(0);
    }
    if args.fingerprint {
        println!("{}", id.fingerprint);
        return Ok(0);
    }
    let state = State::load(&settings.ssh_dir)?;
    let agent = agent::status();
    let text = render(&id, &state, &agent, &settings.ssh_dir)?;
    ui.info(text.trim_end());
    Ok(0)
}

pub fn render(
    id: &Identity,
    state: &State,
    agent: &AgentStatus,
    ssh_dir: &Path,
) -> anyhow::Result<String> {
    let mut s = String::new();
    writeln!(s, "{}", id.name)?;
    writeln!(s, "  type         {}", id.type_label())?;
    writeln!(s, "  fingerprint  {}", id.fingerprint)?;
    writeln!(
        s,
        "  comment      {}",
        if id.comment.is_empty() {
            "(none)"
        } else {
            &id.comment
        }
    )?;
    writeln!(
        s,
        "  passphrase   {}",
        if id.encrypted { "yes" } else { "no" }
    )?;
    writeln!(
        s,
        "  in agent     {}",
        match agent::contains(agent, &id.fingerprint) {
            Some(true) => "yes",
            Some(false) => "no",
            None => "n/a (no agent)",
        }
    )?;
    writeln!(
        s,
        "  private      {}  (mode {:04o})",
        id.private_path.display(),
        fsx::mode_of(&id.private_path)?
    )?;
    match &id.public_path {
        Some(p) => writeln!(
            s,
            "  public       {}  (mode {:04o})",
            p.display(),
            fsx::mode_of(p)?
        )?,
        None => writeln!(s, "  public       (missing; run `ssk doctor --fix`)")?,
    }
    let created = state
        .identity
        .get(&id.name)
        .and_then(|x| x.created.as_deref());
    writeln!(
        s,
        "  created      {}",
        created.unwrap_or("unknown (not created by ssk)")
    )?;
    let deployments = state.deployments(&id.name);
    if deployments.is_empty() {
        writeln!(s, "  hosts        none recorded")?;
    } else {
        writeln!(s, "  hosts")?;
        for d in deployments {
            writeln!(
                s,
                "    {:<28} alias {:<16} installed {}",
                endpoint(d),
                d.alias,
                d.installed
            )?;
        }
    }
    let conf = ssh_dir.join("ssk.d").join(format!("{}.conf", id.name));
    if conf.is_file() {
        writeln!(s, "  ssh config   {}", conf.display())?;
    }
    if let Ok(line) = id.public_key_line() {
        writeln!(s)?;
        writeln!(s, "{line}")?;
    }
    Ok(s)
}

fn endpoint(d: &Deployment) -> String {
    let mut e = String::new();
    if let Some(u) = &d.user {
        e.push_str(u);
        e.push('@');
    }
    e.push_str(&d.host);
    if d.port != 22 {
        e.push_str(&format!(":{}", d.port));
    }
    e
}
