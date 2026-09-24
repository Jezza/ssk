//! `ssk revoke <IDENTITY> <TARGET>... | --all`: remove the public key from each host,
//! verify it no longer authenticates, forget the deployment.

use std::io;
use std::path::Path;

use anyhow::{Context, bail};

use crate::cmd::copy;
use crate::identity::Identity;
use crate::identity::store;
use crate::settings::Settings;
use crate::ssh::probe::{self, ProbeResult};
use crate::ssh::revoke::{self, RevokeResult};
use crate::ssh::runner::SshRunner;
use crate::ssh::{agent, config};
use crate::state::State;
use crate::target::Target;
use crate::ui::{Ui, shell_join};

#[derive(clap::Parser, Debug)]
#[command(group = clap::ArgGroup::new("where").args(["targets", "all"]).required(true))]
pub struct Revoke {
    /// Identity whose public key to remove
    pub identity: String,

    /// [user@]host[:port]
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Every host recorded for this identity in ssk.toml
    #[arg(long)]
    pub all: bool,

    /// Default port for targets that don't specify one
    #[arg(short = 'p', long, value_name = "N")]
    pub port: Option<u16>,

    /// Default user for targets that don't specify one
    #[arg(short = 'l', long, value_name = "USER")]
    pub login: Option<String>,

    /// Extra ssh option, passed through as -o (repeatable)
    #[arg(short = 'o', long = "ssh-option", value_name = "K=V", action = clap::ArgAction::Append)]
    pub ssh_option: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Revoked,
    NotPresent,
    /// The snippet removed it, but the verify probe could not connect.
    RevokedUnverified(String),
    /// Removed (or never there), yet the key still authenticates.
    StillAccepted,
    /// ssh exited 255: could not connect or authenticate.
    Unreachable(String),
    Failed(String),
    DryRun,
}

impl Outcome {
    /// The host no longer has the key: drop the deployment record.
    pub fn forget(&self) -> bool {
        matches!(
            self,
            Outcome::Revoked | Outcome::NotPresent | Outcome::RevokedUnverified(_)
        )
    }

    /// Counts as success for the exit code.
    pub fn ok(&self) -> bool {
        matches!(
            self,
            Outcome::Revoked | Outcome::NotPresent | Outcome::DryRun
        )
    }
}

/// Short human form for callers that print their own status lines.
pub fn describe(o: &Outcome) -> String {
    match o {
        Outcome::Revoked => "revoked and verified".to_string(),
        Outcome::NotPresent => "not present".to_string(),
        Outcome::RevokedUnverified(m) => {
            format!("removed, but verification could not connect: {m}")
        }
        Outcome::StillAccepted => "the key still authenticates after removal".to_string(),
        Outcome::Unreachable(m) => format!("could not connect: {m}"),
        Outcome::Failed(m) => format!("removal failed: {m}"),
        Outcome::DryRun => "dry run".to_string(),
    }
}

/// Targets for `--all`: every recorded deployment, as recorded.
pub fn recorded_targets(state: &State, name: &str) -> Vec<Target> {
    state
        .deployments(name)
        .iter()
        .map(|d| Target {
            user: d.user.clone(),
            host: d.host.clone(),
            port: Some(d.port),
        })
        .collect()
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Revoke) -> anyhow::Result<u8> {
    let identity = store::resolve(&settings.ssh_dir, &args.identity)?;
    let targets = if args.all {
        let st = State::load(&settings.ssh_dir)?;
        let targets = recorded_targets(&st, &identity.name);
        if targets.is_empty() {
            bail!(
                "no deployments recorded for '{}' in {}; name the hosts explicitly",
                identity.name,
                State::path(&settings.ssh_dir).display()
            );
        }
        targets
    } else {
        copy::parse_targets(&args.targets, args.login.as_deref(), args.port)?
    };
    let runner = copy::runner_for(settings)?;
    let auth_key = identity.private_path.clone();
    run_targets(
        settings,
        ui,
        &identity,
        &auth_key,
        &targets,
        &args.ssh_option,
        runner.as_deref(),
    )
}

/// `auth_key` is what ssh logs in with: the identity itself for `revoke`, the new key
/// for `rotate`. The verify probe always uses the identity being revoked.
pub fn run_targets(
    settings: &Settings,
    ui: &Ui,
    identity: &Identity,
    auth_key: &Path,
    targets: &[Target],
    ssh_options: &[String],
    runner: Option<&dyn SshRunner>,
) -> anyhow::Result<u8> {
    let public_line = identity.public_key_line()?;
    if runner.is_some()
        && identity.encrypted
        && agent::contains(&agent::status(), &identity.fingerprint) != Some(true)
    {
        ui.warn(format!(
            "'{}' is passphrase-protected and not in ssh-agent; ssh will ask for its passphrase to verify each host. `ssk add {}` avoids that.",
            identity.name, identity.name
        ));
    }
    let dir = &settings.ssh_dir;
    let mut st = State::load(dir)?;
    let mut outcomes = Vec::new();
    for target in targets {
        let outcome = match runner {
            None => {
                describe_dry_run(
                    ui,
                    dir,
                    identity,
                    auth_key,
                    target,
                    ssh_options,
                    &public_line,
                );
                Outcome::DryRun
            }
            Some(r) => revoke_one(r, ui, identity, auth_key, target, ssh_options, &public_line)
                .with_context(|| format!("{target}: running ssh"))?,
        };
        if outcome.forget() {
            st.remove_deployments(
                &identity.name,
                &target.host,
                target.user.as_deref(),
                target.port.unwrap_or(22),
            );
        }
        outcomes.push((target, outcome));
    }
    if outcomes.iter().any(|(_, o)| o.forget()) {
        st.save(dir)?;
        let conf = config::conf_path(dir, &identity.name);
        if conf.is_file() {
            match config::sync_conf(dir, &identity.name, st.deployments(&identity.name))? {
                Some(p) => ui.info(format!("ssh config written: {}", p.display())),
                None => ui.info(format!("ssh config removed: {}", conf.display())),
            }
        }
    }
    let mut all_ok = true;
    for (target, outcome) in &outcomes {
        report(ui, identity, target, outcome);
        all_ok &= outcome.ok();
    }
    Ok(if all_ok { 0 } else { 1 })
}

/// Remove, then verify with the revoked key. Only spawn errors are `Err`.
pub fn revoke_one(
    runner: &dyn SshRunner,
    ui: &Ui,
    identity: &Identity,
    auth_key: &Path,
    target: &Target,
    ssh_options: &[String],
    public_line: &str,
) -> io::Result<Outcome> {
    ui.info(format!(
        "{target}: removing '{}' (ssh may ask for a password or passphrase)",
        identity.name
    ));
    let removed = match revoke::revoke(runner, auth_key, target, ssh_options, public_line)? {
        RevokeResult::Removed => true,
        RevokeResult::RemovedUnlabeled => {
            ui.warn(format!(
                "{target}: removed, but restorecon failed afterwards; check the SELinux label of authorized_keys on the host"
            ));
            true
        }
        RevokeResult::NotPresent => false,
        RevokeResult::Failed { code: Some(255) } => {
            return Ok(Outcome::Unreachable(
                "ssh exited with 255 (could not connect or authenticate; see its output above)"
                    .to_string(),
            ));
        }
        RevokeResult::Failed { code } => {
            let status = code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "a signal".to_string());
            return Ok(Outcome::Failed(format!(
                "remote command exited with {status}"
            )));
        }
    };
    ui.info(format!("{target}: verifying"));
    Ok(
        match probe::probe(
            runner,
            &identity.private_path,
            &identity.fingerprint,
            target,
            ssh_options,
        )? {
            ProbeResult::NotInstalled if removed => Outcome::Revoked,
            ProbeResult::NotInstalled => Outcome::NotPresent,
            ProbeResult::Installed => Outcome::StillAccepted,
            ProbeResult::Error(msg) | ProbeResult::HostKeyChanged(msg) if removed => {
                Outcome::RevokedUnverified(msg)
            }
            ProbeResult::Error(_) | ProbeResult::HostKeyChanged(_) => Outcome::NotPresent,
        },
    )
}

fn describe_dry_run(
    ui: &Ui,
    ssh_dir: &Path,
    identity: &Identity,
    auth_key: &Path,
    target: &Target,
    ssh_options: &[String],
    public_line: &str,
) {
    let remove = revoke::invocation(auth_key, target, ssh_options, public_line);
    let verify = probe::invocation(&identity.private_path, target, ssh_options);
    ui.info(format!("{target}: would run"));
    ui.info(format!(
        "  ssh {}   (public key on stdin)",
        shell_join(&remove.args)
    ));
    ui.info(format!("  ssh {}", shell_join(&verify.args)));
    ui.info(format!(
        "  forget the deployment in {}",
        State::path(ssh_dir).display()
    ));
    if config::conf_path(ssh_dir, &identity.name).is_file() {
        ui.info(format!(
            "  rewrite or remove {}",
            config::conf_path(ssh_dir, &identity.name).display()
        ));
    }
}

fn report(ui: &Ui, identity: &Identity, target: &Target, outcome: &Outcome) {
    match outcome {
        Outcome::Revoked | Outcome::NotPresent => {
            ui.success(format!("{target}: {}", describe(outcome)))
        }
        Outcome::RevokedUnverified(_) => ui.warn(format!("{target}: {}", describe(outcome))),
        Outcome::StillAccepted => ui.error(format!(
            "{target}: '{}' still authenticates after removal; look for another AuthorizedKeysFile or a line ssk did not recognise",
            identity.name
        )),
        Outcome::Unreachable(_) | Outcome::Failed(_) => {
            ui.error(format!("{target}: {}", describe(outcome)))
        }
        Outcome::DryRun => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keygen::{KeySpec, KeyType, generate, write_pair};
    use crate::ssh::runner::SshOutput;
    use crate::ssh::runner::fake::{FakeSsh, accepts, denied, ok, unreachable};
    use crate::state::Deployment;

    fn fixture() -> (tempfile::TempDir, Identity) {
        let tmp = tempfile::tempdir().unwrap();
        let key = generate(
            &KeySpec {
                key_type: KeyType::Ed25519,
                bits: None,
                comment: "work@box".into(),
            },
            None,
        )
        .unwrap();
        write_pair(tmp.path(), "work", &key, false).unwrap();
        let id = Identity::load(tmp.path(), "work").unwrap();
        (tmp, id)
    }

    fn t() -> Target {
        Target {
            user: Some("deploy".into()),
            host: "example.test".into(),
            port: Some(2222),
        }
    }

    fn not_present() -> SshOutput {
        SshOutput {
            code: Some(3),
            ..Default::default()
        }
    }

    #[test]
    fn removed_then_denied_is_revoked() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![ok(), denied()]);
        let out = revoke_one(&ssh, &Ui::silent(), &id, &id.private_path, &t(), &[], "k").unwrap();
        assert_eq!(out, Outcome::Revoked);
        let calls = ssh.calls();
        assert_eq!(calls.len(), 2);
        assert!(!calls[0].capture && calls[0].stdin.as_deref() == Some("k\n"));
        assert!(calls[1].capture && calls[1].args.last().map(String::as_str) == Some("exit"));
    }

    /// The verify probe got in, but on another key (an ssk.d conf for a different
    /// identity, say): the key we removed is gone all the same.
    #[test]
    fn a_foreign_key_authenticating_after_removal_is_still_revoked() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![ok(), ok()]);
        let out = revoke_one(&ssh, &Ui::silent(), &id, &id.private_path, &t(), &[], "k").unwrap();
        assert_eq!(out, Outcome::Revoked);
    }

    #[test]
    fn other_results() {
        let (_tmp, id) = fixture();
        let run = |responses| {
            let ssh = FakeSsh::new(responses);
            revoke_one(&ssh, &Ui::silent(), &id, &id.private_path, &t(), &[], "k").unwrap()
        };
        assert_eq!(run(vec![not_present(), denied()]), Outcome::NotPresent);
        assert_eq!(
            run(vec![ok(), accepts(&id.private_path)]),
            Outcome::StillAccepted
        );
        assert_eq!(
            run(vec![not_present(), accepts(&id.private_path)]),
            Outcome::StillAccepted
        );
        assert!(matches!(
            run(vec![ok(), unreachable()]),
            Outcome::RevokedUnverified(_)
        ));
        assert!(matches!(
            run(vec![SshOutput {
                code: Some(255),
                ..Default::default()
            }]),
            Outcome::Unreachable(_)
        ));
        assert!(matches!(
            run(vec![SshOutput {
                code: Some(1),
                ..Default::default()
            }]),
            Outcome::Failed(_)
        ));
        assert_eq!(
            run(vec![
                SshOutput {
                    code: Some(4),
                    ..Default::default()
                },
                denied()
            ]),
            Outcome::Revoked
        );
    }

    #[test]
    fn run_targets_forgets_and_syncs_config() {
        let (tmp, id) = fixture();
        let settings = Settings::for_dir(tmp.path());
        let mut st = State::default();
        for (host, user) in [("a", Some("deploy")), ("b", None)] {
            st.record_deployment(
                "work",
                Deployment {
                    host: host.into(),
                    user: user.map(String::from),
                    port: 22,
                    alias: host.into(),
                    installed: "t".into(),
                },
            );
        }
        st.save(tmp.path()).unwrap();
        config::write_conf(tmp.path(), "work", st.deployments("work")).unwrap();

        let ssh = FakeSsh::new(vec![ok(), denied()]);
        let targets = vec![Target {
            user: None,
            host: "a".into(),
            port: None,
        }];
        let code = run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &id.private_path,
            &targets,
            &[],
            Some(&ssh as &dyn SshRunner),
        )
        .unwrap();
        assert_eq!(code, 0);
        let st = State::load(tmp.path()).unwrap();
        assert_eq!(st.deployments("work").len(), 1);
        assert_eq!(st.deployments("work")[0].host, "b");
        let conf = std::fs::read_to_string(tmp.path().join("ssk.d/work.conf")).unwrap();
        assert!(
            conf.contains("Host b\n") && !conf.contains("Host a\n"),
            "{conf}"
        );

        let ssh = FakeSsh::new(vec![ok(), denied()]);
        let all = recorded_targets(&st, "work");
        assert_eq!(all.len(), 1);
        run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &id.private_path,
            &all,
            &[],
            Some(&ssh as &dyn SshRunner),
        )
        .unwrap();
        assert!(
            State::load(tmp.path())
                .unwrap()
                .deployments("work")
                .is_empty()
        );
        assert!(!tmp.path().join("ssk.d/work.conf").exists());
    }

    #[test]
    fn still_accepted_keeps_the_record_and_fails() {
        let (tmp, id) = fixture();
        let settings = Settings::for_dir(tmp.path());
        let mut st = State::default();
        st.record_deployment(
            "work",
            Deployment {
                host: "a".into(),
                user: None,
                port: 22,
                alias: "a".into(),
                installed: "t".into(),
            },
        );
        st.save(tmp.path()).unwrap();
        let ssh = FakeSsh::new(vec![ok(), accepts(&id.private_path)]);
        let code = run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &id.private_path,
            &recorded_targets(&st, "work"),
            &[],
            Some(&ssh as &dyn SshRunner),
        )
        .unwrap();
        assert_eq!(code, 1);
        assert_eq!(
            State::load(tmp.path()).unwrap().deployments("work").len(),
            1
        );
    }

    #[test]
    fn dry_run_makes_no_calls() {
        let (tmp, id) = fixture();
        let settings = Settings::for_dir(tmp.path());
        let code = run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &id.private_path,
            &[t()],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(code, 0);
    }
}
