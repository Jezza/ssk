//! `ssk alias <NEW> <TARGET>`: change the `Host` name of a recorded deployment. Purely
//! local: ssk.toml and the identity's ssk.d file are rewritten, no host is contacted.

use anyhow::bail;

use crate::settings::Settings;
use crate::ssh::config;
use crate::state::{Deployment, State};
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Alias {
    /// New Host alias
    #[arg(required_unless_present = "reset")]
    pub new: Option<String>,

    /// Deployment to change: its current alias, its host, or user@host[:port]
    #[arg(required_unless_present = "reset")]
    pub target: Option<String>,

    /// Set the alias of TARGET back to its plain host
    #[arg(long, value_name = "TARGET", conflicts_with_all = ["new", "target"])]
    pub reset: Option<String>,

    /// Only consider this identity's deployments
    #[arg(short = 'i', long, value_name = "IDENTITY")]
    pub identity: Option<String>,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Alias) -> anyhow::Result<u8> {
    let dir = &settings.ssh_dir;
    let target = args
        .reset
        .as_deref()
        .or(args.target.as_deref())
        .expect("clap requires a target");
    let mut st = State::load(dir)?;
    if let Some(name) = &args.identity
        && st.deployments(name).is_empty()
    {
        bail!("identity '{name}' has no recorded deployments");
    }

    let (name, idx) = match find(&st, args.identity.as_deref(), target).as_slice() {
        [] => bail!("no deployment matches '{target}'; `ssk hosts` lists them"),
        [one] => one.clone(),
        many => {
            let list: Vec<String> = many
                .iter()
                .map(|(n, i)| format!("  {}", describe(&st, n, *i)))
                .collect();
            bail!(
                "'{target}' matches {} deployments; narrow it with -i IDENTITY or user@host:port:\n{}",
                many.len(),
                list.join("\n")
            );
        }
    };
    let dep = &st.deployments(&name)[idx];
    let new = match (&args.reset, &args.new) {
        (Some(_), _) => dep.host.clone(),
        (None, Some(n)) => n.clone(),
        (None, None) => unreachable!("clap requires NEW without --reset"),
    };
    config::validate_alias(&new)?;
    let what = describe(&st, &name, idx);
    if dep.alias == new {
        ui.info(format!("{what} is already aliased '{new}'"));
        return Ok(0);
    }
    if let Some((n, i)) = taken_by(&st, &new, (&name, idx)) {
        bail!(
            "'{new}' is already the alias of {}; ssh would only ever use the first",
            describe(&st, &n, i)
        );
    }

    ui.info(format!("{what}: alias '{}' -> '{new}'", dep.alias));
    if settings.dry_run {
        ui.info("dry run: nothing changed");
        return Ok(0);
    }
    st.set_alias(&name, idx, new);
    st.save(dir)?;
    let write = config::conf_path(dir, &name).is_file() || settings.write_ssh_config;
    if write {
        let conf = config::write_conf(dir, &name, st.deployments(&name))?;
        if config::ensure_include(dir)? {
            ui.info(format!(
                "added `{}` to {}",
                config::include_line(dir),
                dir.join("config").display()
            ));
        }
        ui.info(format!("ssh config written: {}", conf.display()));
    }
    Ok(0)
}

/// Deployments `target` names, as (identity, index). Aliases are tried first, then
/// hosts, then `user@host:port`, so a name that is both an alias and some other
/// deployment's host picks the alias.
fn find(st: &State, identity: Option<&str>, target: &str) -> Vec<(String, usize)> {
    let all: Vec<(&String, usize, &Deployment)> = st
        .identity
        .iter()
        .filter(|(n, _)| identity.is_none_or(|want| want == n.as_str()))
        .flat_map(|(n, s)| {
            s.deployments
                .iter()
                .enumerate()
                .map(move |(i, d)| (n, i, d))
        })
        .collect();
    let matches = |d: &Deployment, tier: u8| match tier {
        0 => d.alias == target,
        1 => d.host == target,
        _ => d.endpoint() == target,
    };
    (0..3)
        .map(|tier| {
            all.iter()
                .filter(|(_, _, d)| matches(d, tier))
                .map(|(n, i, _)| ((*n).clone(), *i))
                .collect::<Vec<_>>()
        })
        .find(|hits| !hits.is_empty())
        .unwrap_or_default()
}

/// Another deployment, of any identity, already written as `Host <alias>`. Every
/// ssk.d file is included, so a clash across identities is still a clash.
fn taken_by(st: &State, alias: &str, me: (&str, usize)) -> Option<(String, usize)> {
    st.identity.iter().find_map(|(n, s)| {
        s.deployments
            .iter()
            .enumerate()
            .find(|(i, d)| d.alias == alias && (n.as_str(), *i) != me)
            .map(|(i, _)| (n.clone(), i))
    })
}

fn describe(st: &State, name: &str, idx: usize) -> String {
    let d = &st.deployments(name)[idx];
    if d.alias == d.host {
        format!("{name}: {}", d.endpoint())
    } else {
        format!("{name}: {} (alias {})", d.endpoint(), d.alias)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(host: &str, user: Option<&str>, port: u16, alias: &str) -> Deployment {
        Deployment {
            host: host.into(),
            user: user.map(Into::into),
            port,
            alias: alias.into(),
            installed: "t".into(),
        }
    }

    fn st() -> State {
        let mut s = State::default();
        s.record_deployment("work", dep("a.test", Some("u"), 22, "a"));
        s.record_deployment("work", dep("a", None, 22, "a"));
        s.record_deployment("work", dep("b.test", Some("u"), 2222, "b.test"));
        s.record_deployment("home", dep("b.test", None, 22, "b.test"));
        s
    }

    #[test]
    fn alias_beats_host_and_endpoint_is_last() {
        let s = st();
        // "a" is the alias of both work deployments; the host "a" is never reached.
        assert_eq!(find(&s, None, "a").len(), 2);
        assert_eq!(find(&s, None, "b.test").len(), 2);
        assert_eq!(find(&s, None, "u@b.test:2222"), vec![("work".into(), 2)]);
        assert_eq!(find(&s, Some("home"), "b.test"), vec![("home".into(), 0)]);
        assert!(find(&s, None, "c.test").is_empty());
    }

    #[test]
    fn taken_ignores_the_deployment_itself() {
        let s = st();
        assert_eq!(taken_by(&s, "a", ("work", 0)), Some(("work".into(), 1)));
        assert_eq!(
            taken_by(&s, "b.test", ("home", 0)),
            Some(("work".into(), 2))
        );
        assert_eq!(taken_by(&s, "zzz", ("work", 0)), None);
    }
}
