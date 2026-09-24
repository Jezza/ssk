//! `ssk show <IDENTITY>`: everything ssk knows about one identity.

use std::fmt::Write as _;
use std::path::Path;

use crate::fsx;
use crate::identity::Identity;
use crate::identity::store;
use crate::json::{self, DeploymentJson, IdentityFields, ShowJson};
use crate::settings::Settings;
use crate::ssh::agent::{self, AgentStatus};
use crate::state::State;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Show {
    /// Identity to show
    pub identity: String,

    /// Print only the public key line
    #[arg(short = 'p', long = "pub")]
    pub pub_only: bool,

    /// Print only the SHA256 fingerprint
    #[arg(long, conflicts_with = "pub_only")]
    pub fingerprint: bool,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Show) -> anyhow::Result<u8> {
    let id = store::resolve(&settings.ssh_dir, &args.identity)?;
    if settings.json {
        let state = State::load(&settings.ssh_dir)?;
        let agent = agent::status();
        json::print(&render_json(&id, &state, &agent, &settings.ssh_dir)?)?;
        return Ok(0);
    }
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
                d.endpoint(),
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

pub fn render_json(
    id: &Identity,
    state: &State,
    agent: &AgentStatus,
    ssh_dir: &Path,
) -> anyhow::Result<ShowJson> {
    let conf = ssh_dir.join("ssk.d").join(format!("{}.conf", id.name));
    Ok(ShowJson {
        status: json::status_of(id),
        identity: IdentityFields::new(id, state, agent),
        private_mode: format!("{:04o}", fsx::mode_of(&id.private_path)?),
        public_mode: id
            .public_path
            .as_ref()
            .map(|p| fsx::mode_of(p))
            .transpose()?
            .map(|m| format!("{m:04o}")),
        created: state.identity.get(&id.name).and_then(|x| x.created.clone()),
        deployments: state
            .deployments(&id.name)
            .iter()
            .map(DeploymentJson::from)
            .collect(),
        ssh_config: conf.is_file().then_some(conf),
        public_key: id.public_key_line().ok(),
    })
}
