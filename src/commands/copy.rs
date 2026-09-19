//! `ssk copy <IDENTITY> <TARGET>...`: probe, install, verify, record, write ssh config.

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::cli::CopyArgs;
use crate::identity::Identity;
use crate::identity::store;
use crate::settings::Settings;
use crate::ssh::runner::{RealSsh, SshRunner};
use crate::ssh::{agent, config, install, probe};
use crate::state::{self, Deployment, State};
use crate::target::{self, Target};
use crate::ui::{Ui, shell_join};

#[derive(Debug, Clone)]
pub struct CopyOptions {
    pub ssh_options: Vec<String>,
    pub alias: Option<String>,
    pub write_config: bool,
    pub force: bool,
    /// Extra -i for the install step; rotate passes the current key.
    pub auth_key: Option<PathBuf>,
}

impl Default for CopyOptions {
    fn default() -> Self {
        CopyOptions {
            ssh_options: Vec::new(),
            alias: None,
            write_config: true,
            force: false,
            auth_key: None,
        }
    }
}

impl CopyOptions {
    /// Flags win; when neither `--write-config` nor `--no-config` is given the setting decides.
    pub fn from_args(a: &CopyArgs, settings: &Settings) -> Self {
        CopyOptions {
            ssh_options: a.ssh_option.clone(),
            alias: a.alias.clone(),
            write_config: if a.write_config {
                true
            } else if a.no_config {
                false
            } else {
                settings.write_ssh_config
            },
            force: a.force,
            auth_key: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    AlreadyInstalled,
    Installed,
    /// Appended, but the verify probe was still denied (locked key, or sshd ignores the file).
    InstalledUnverified,
    /// The probe could not even get a "Permission denied" out of the host.
    Unreachable(String),
    Failed(String),
    DryRun,
}

impl Outcome {
    /// The key is on the host: record the deployment and write config.
    pub fn key_present(&self) -> bool {
        matches!(
            self,
            Outcome::AlreadyInstalled | Outcome::Installed | Outcome::InstalledUnverified
        )
    }

    /// Counts as success for the exit code.
    pub fn ok(&self) -> bool {
        matches!(
            self,
            Outcome::AlreadyInstalled | Outcome::Installed | Outcome::DryRun
        )
    }
}

pub fn parse_targets(
    raw: &[String],
    login: Option<&str>,
    port: Option<u16>,
) -> anyhow::Result<Vec<Target>> {
    raw.iter()
        .map(|r| Ok(target::parse(r)?.with_defaults(login, port)))
        .collect()
}

/// `None` in dry-run mode, otherwise the real `ssh`.
pub fn runner_for(settings: &Settings) -> anyhow::Result<Option<Box<dyn SshRunner>>> {
    if settings.dry_run {
        return Ok(None);
    }
    Ok(Some(Box::new(RealSsh::locate(settings.verbose)?)))
}

pub fn run(settings: &Settings, ui: &Ui, args: &CopyArgs) -> anyhow::Result<u8> {
    let identity = store::resolve(&settings.ssh_dir, &args.identity)?;
    let opts = CopyOptions::from_args(args, settings);
    if opts.alias.is_some() && args.targets.len() != 1 {
        bail!(
            "--alias applies to exactly one target; got {}",
            args.targets.len()
        );
    }
    let targets = parse_targets(&args.targets, args.login.as_deref(), args.port)?;
    let runner = runner_for(settings)?;
    run_targets(settings, ui, &identity, &targets, &opts, runner.as_deref())
}

pub fn run_targets(
    settings: &Settings,
    ui: &Ui,
    identity: &Identity,
    targets: &[Target],
    opts: &CopyOptions,
    runner: Option<&dyn SshRunner>,
) -> anyhow::Result<u8> {
    let public_line = identity.public_key_line()?;
    if runner.is_some()
        && identity.encrypted
        && agent::contains(&agent::status(), &identity.fingerprint) != Some(true)
    {
        ui.warn(format!(
            "'{}' is passphrase-protected and not in ssh-agent; ssh will ask for its passphrase to check each host. `ssh-add {}` avoids that.",
            identity.name,
            identity.private_path.display()
        ));
    }

    let mut st = State::load(&settings.ssh_dir)?;
    let mut outcomes = Vec::new();
    for target in targets {
        let outcome = match runner {
            None => {
                describe_dry_run(ui, &settings.ssh_dir, identity, target, opts, &public_line);
                Outcome::DryRun
            }
            Some(r) => copy_one(r, ui, identity, target, opts, &public_line)
                .with_context(|| format!("{target}: running ssh"))?,
        };
        if outcome.key_present() {
            st.record_deployment(
                &identity.name,
                Deployment {
                    host: target.host.clone(),
                    user: target.user.clone(),
                    port: target.port.unwrap_or(22),
                    alias: opts.alias.clone().unwrap_or_else(|| target.host.clone()),
                    installed: state::now(),
                },
            );
        }
        outcomes.push((target, outcome));
    }

    if outcomes.iter().any(|(_, o)| o.key_present()) {
        st.save(&settings.ssh_dir)?;
        if opts.write_config {
            let conf = config::write_conf(
                &settings.ssh_dir,
                &identity.name,
                st.deployments(&identity.name),
            )?;
            if config::ensure_include(&settings.ssh_dir)? {
                ui.info(format!(
                    "added `{}` to {}",
                    config::include_line(&settings.ssh_dir),
                    settings.ssh_dir.join("config").display()
                ));
            }
            ui.info(format!("ssh config written: {}", conf.display()));
        }
    }

    let mut all_ok = true;
    for (target, outcome) in &outcomes {
        report(ui, identity, target, outcome);
        all_ok &= outcome.ok();
    }
    Ok(if all_ok { 0 } else { 1 })
}

/// Probe, install, verify for one host. Only I/O errors from spawning ssh are `Err`;
/// everything ssh itself reports becomes an `Outcome`.
pub fn copy_one(
    runner: &dyn SshRunner,
    ui: &Ui,
    identity: &Identity,
    target: &Target,
    opts: &CopyOptions,
    public_line: &str,
) -> io::Result<Outcome> {
    ui.info(format!(
        "{target}: checking whether '{}' already works",
        identity.name
    ));
    match probe::probe(
        runner,
        &identity.private_path,
        &identity.fingerprint,
        target,
        &opts.ssh_options,
    )? {
        probe::ProbeResult::Installed if !opts.force => return Ok(Outcome::AlreadyInstalled),
        probe::ProbeResult::Installed | probe::ProbeResult::NotInstalled => {}
        probe::ProbeResult::Error(msg) => return Ok(Outcome::Unreachable(msg)),
    }

    ui.info(format!(
        "{target}: installing '{}' (ssh may ask for your password)",
        identity.name
    ));
    if let install::InstallResult::Failed { code } = install::install(
        runner,
        target,
        &opts.ssh_options,
        public_line,
        opts.auth_key.as_deref(),
    )? {
        let status = code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "a signal".to_string());
        return Ok(Outcome::Failed(format!("ssh exited with {status}")));
    }

    ui.info(format!("{target}: verifying"));
    Ok(
        match probe::probe(
            runner,
            &identity.private_path,
            &identity.fingerprint,
            target,
            &opts.ssh_options,
        )? {
            probe::ProbeResult::Installed => Outcome::Installed,
            probe::ProbeResult::NotInstalled => Outcome::InstalledUnverified,
            probe::ProbeResult::Error(msg) => {
                Outcome::Failed(format!("verification could not connect: {msg}"))
            }
        },
    )
}

fn describe_dry_run(
    ui: &Ui,
    ssh_dir: &Path,
    identity: &Identity,
    target: &Target,
    opts: &CopyOptions,
    public_line: &str,
) {
    let probe_inv = probe::invocation(&identity.private_path, target, &opts.ssh_options);
    let install_inv = install::invocation(
        target,
        &opts.ssh_options,
        public_line,
        opts.auth_key.as_deref(),
    );
    ui.info(format!("{target}: would run"));
    ui.info(format!("  ssh {}", shell_join(&probe_inv.args)));
    ui.info(format!(
        "  ssh {}   (public key on stdin)",
        shell_join(&install_inv.args)
    ));
    ui.info(format!("  ssh {}", shell_join(&probe_inv.args)));
    ui.info(format!(
        "  record the deployment in {}",
        State::path(ssh_dir).display()
    ));
    if opts.write_config {
        ui.info(format!(
            "  write {}",
            config::conf_path(ssh_dir, &identity.name).display()
        ));
    }
}

fn report(ui: &Ui, identity: &Identity, target: &Target, outcome: &Outcome) {
    match outcome {
        Outcome::AlreadyInstalled => ui.success(format!("{target}: already installed")),
        Outcome::Installed => ui.success(format!("{target}: installed and verified")),
        Outcome::InstalledUnverified => ui.warn(format!(
            "{target}: installed, but verification failed. If '{}' is passphrase-protected and you did not unlock it, this is expected. Otherwise check sshd_config on the host (PubkeyAuthentication, AuthorizedKeysFile).",
            identity.name
        )),
        Outcome::Unreachable(msg) => ui.error(format!("{target}: could not connect: {msg}")),
        Outcome::Failed(msg) => ui.error(format!("{target}: install failed: {msg}")),
        Outcome::DryRun => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keygen::{KeySpec, KeyType, generate, write_pair};
    use crate::ssh::runner::SshOutput;
    use crate::ssh::runner::fake::{FakeSsh, accepts, denied, ok, unreachable};

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

    #[test]
    fn already_installed_makes_one_call() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![accepts(&id.private_path)]);
        let out = copy_one(
            &ssh,
            &Ui::silent(),
            &id,
            &t(),
            &CopyOptions::default(),
            "ssh-ed25519 AAAA",
        )
        .unwrap();
        assert_eq!(out, Outcome::AlreadyInstalled);
        assert_eq!(ssh.calls().len(), 1);
    }

    /// ssh got in, but on some other key (a config `IdentityFile` line, ssk's own
    /// ssk.d conf for another identity): our key is not there, so install it.
    #[test]
    fn another_key_authenticating_is_not_already_installed() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![ok(), ok(), accepts(&id.private_path)]);
        let out = copy_one(&ssh, &Ui::silent(), &id, &t(), &CopyOptions::default(), "k").unwrap();
        assert_eq!(out, Outcome::Installed);
        assert_eq!(ssh.calls().len(), 3, "probe, install, verify");
    }

    #[test]
    fn install_then_verify() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![denied(), ok(), accepts(&id.private_path)]);
        let out = copy_one(
            &ssh,
            &Ui::silent(),
            &id,
            &t(),
            &CopyOptions::default(),
            "ssh-ed25519 AAAA c",
        )
        .unwrap();
        assert_eq!(out, Outcome::Installed);
        let calls = ssh.calls();
        assert_eq!(calls.len(), 3);
        assert!(calls[0].capture);
        assert!(calls[0].args.contains(&"-i".to_string()));
        assert_eq!(calls[1].stdin.as_deref(), Some("ssh-ed25519 AAAA c\n"));
        assert!(!calls[1].args.contains(&"-i".to_string()));
        let dd = calls[1].args.iter().position(|a| a == "--").unwrap();
        assert_eq!(calls[1].args[dd + 1], "example.test");
        assert!(calls[1].args[dd + 2].starts_with("exec sh -c '"));
        assert_eq!(calls[2].args, calls[0].args);
    }

    #[test]
    fn install_ok_but_verify_denied_is_unverified() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![denied(), ok(), denied()]);
        let out = copy_one(&ssh, &Ui::silent(), &id, &t(), &CopyOptions::default(), "k").unwrap();
        assert_eq!(out, Outcome::InstalledUnverified);
        assert!(out.key_present());
        assert!(!out.ok());
    }

    #[test]
    fn probe_error_means_unreachable_and_no_install_attempt() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![unreachable()]);
        let out = copy_one(&ssh, &Ui::silent(), &id, &t(), &CopyOptions::default(), "k").unwrap();
        assert!(matches!(out, Outcome::Unreachable(ref m) if m.contains("No route to host")));
        assert_eq!(ssh.calls().len(), 1);
    }

    #[test]
    fn force_reinstalls_even_when_already_working() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![
            accepts(&id.private_path),
            ok(),
            accepts(&id.private_path),
        ]);
        let opts = CopyOptions {
            force: true,
            ..Default::default()
        };
        assert_eq!(
            copy_one(&ssh, &Ui::silent(), &id, &t(), &opts, "k").unwrap(),
            Outcome::Installed
        );
        assert_eq!(ssh.calls().len(), 3);
    }

    #[test]
    fn install_failure_is_reported() {
        let (_tmp, id) = fixture();
        let ssh = FakeSsh::new(vec![
            denied(),
            SshOutput {
                code: Some(255),
                ..Default::default()
            },
        ]);
        let out = copy_one(&ssh, &Ui::silent(), &id, &t(), &CopyOptions::default(), "k").unwrap();
        assert!(matches!(out, Outcome::Failed(ref m) if m.contains("255")));
    }

    #[test]
    fn run_targets_records_state_writes_config_and_sets_exit_code() {
        let (tmp, id) = fixture();
        let settings = Settings::for_dir(tmp.path());
        let ssh = FakeSsh::new(vec![
            denied(),
            ok(),
            accepts(&id.private_path),
            unreachable(),
        ]);
        let targets = vec![
            t(),
            Target {
                user: None,
                host: "down.test".into(),
                port: None,
            },
        ];
        let code = run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &targets,
            &CopyOptions::default(),
            Some(&ssh as &dyn SshRunner),
        )
        .unwrap();
        assert_eq!(code, 1, "one target failed");

        let st = State::load(tmp.path()).unwrap();
        let deps = st.deployments("work");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].host, "example.test");
        assert_eq!(deps[0].port, 2222);
        assert_eq!(deps[0].user.as_deref(), Some("deploy"));
        assert_eq!(deps[0].alias, "example.test");

        let conf = std::fs::read_to_string(tmp.path().join("ssk.d/work.conf")).unwrap();
        for needle in [
            "Host example.test\n",
            "    User deploy\n",
            "    Port 2222\n",
            "    IdentitiesOnly yes\n",
            "/work\n",
        ] {
            assert!(conf.contains(needle), "{needle:?} missing in:\n{conf}");
        }
        let cfg = std::fs::read_to_string(tmp.path().join("config")).unwrap();
        assert!(
            cfg.starts_with("Include ") && cfg.contains("ssk.d/*.conf\n"),
            "{cfg}"
        );
    }

    #[test]
    fn alias_is_used_when_given() {
        let (tmp, id) = fixture();
        let settings = Settings::for_dir(tmp.path());
        let ssh = FakeSsh::new(vec![accepts(&id.private_path)]);
        let opts = CopyOptions {
            alias: Some("prod1".into()),
            ..Default::default()
        };
        run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &[t()],
            &opts,
            Some(&ssh as &dyn SshRunner),
        )
        .unwrap();
        let conf = std::fs::read_to_string(tmp.path().join("ssk.d/work.conf")).unwrap();
        assert!(
            conf.contains("Host prod1\n    HostName example.test\n"),
            "{conf}"
        );
    }

    #[test]
    fn no_config_skips_ssh_config_but_records_state() {
        let (tmp, id) = fixture();
        let settings = Settings::for_dir(tmp.path());
        let ssh = FakeSsh::new(vec![denied(), ok(), accepts(&id.private_path)]);
        let opts = CopyOptions {
            write_config: false,
            ..Default::default()
        };
        let code = run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &[t()],
            &opts,
            Some(&ssh as &dyn SshRunner),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(
            State::load(tmp.path()).unwrap().deployments("work").len(),
            1
        );
        assert!(!tmp.path().join("ssk.d").exists());
        assert!(!tmp.path().join("config").exists());
    }

    #[test]
    fn dry_run_makes_no_calls_and_records_nothing() {
        let (tmp, id) = fixture();
        let settings = Settings {
            dry_run: true,
            ..Settings::for_dir(tmp.path())
        };
        let code = run_targets(
            &settings,
            &Ui::silent(),
            &id,
            &[t()],
            &CopyOptions::default(),
            None,
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(State::load(tmp.path()).unwrap(), State::default());
        assert!(!tmp.path().join("ssk.d").exists());
    }

    #[test]
    fn parse_targets_applies_defaults_and_fails_fast() {
        let ts = parse_targets(
            &["a".into(), "root@b:22".into()],
            Some("deploy"),
            Some(2222),
        )
        .unwrap();
        assert_eq!(
            ts[0],
            Target {
                user: Some("deploy".into()),
                host: "a".into(),
                port: Some(2222)
            }
        );
        assert_eq!(
            ts[1],
            Target {
                user: Some("root".into()),
                host: "b".into(),
                port: Some(22)
            }
        );
        assert!(parse_targets(&["ok".into(), "-bad".into()], None, None).is_err());
    }
}
