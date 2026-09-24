//! `ssk rotate <IDENTITY>`: generate a replacement key, install it on every recorded host
//! (authenticating with the current key), remove the current key from those hosts
//! (authenticating with the new one), then swap the files. Built from the same probe /
//! install / revoke steps as `copy` and `revoke`; nothing here talks to ssh directly.

use std::fs;
use std::path::Path;

use anyhow::{Context, bail};

use crate::cmd::copy::{self, CopyOptions};
use crate::cmd::{new, revoke as revoke_cmd};
use crate::identity::keygen::{self, KeySpec, KeyType};
use crate::identity::{Identity, comment, store};
use crate::settings::Settings;
use crate::ssh::runner::SshRunner;
use crate::ssh::{agent, install, probe, revoke};
use crate::state::{self, Deployment, State};
use crate::target::Target;
use crate::ui::{Ui, shell_join};

#[derive(clap::Parser, Debug)]
#[command(group = clap::ArgGroup::new("pass").args(["passphrase", "no_passphrase", "passphrase_stdin"]))]
pub struct Rotate {
    /// Identity to rotate
    pub identity: String,

    /// Comment for the new key [default: the current key's comment]
    #[arg(short = 'c', long, visible_short_alias = 'C', value_name = "TEXT")]
    pub comment: Option<String>,

    /// Key type for the new key [default: same as the current key]
    #[arg(
        short = 't',
        long = "type",
        alias = "algo",
        value_enum,
        value_name = "ALGO"
    )]
    pub key_type: Option<KeyType>,

    /// Key size for the new key [default: same as the current key]
    #[arg(short = 'b', long, value_name = "N")]
    pub bits: Option<u32>,

    /// Set the new key's passphrase non-interactively. Visible in `ps` and shell history
    #[arg(short = 'N', long, value_name = "TEXT")]
    pub passphrase: Option<String>,

    /// Create the new key without a passphrase
    #[arg(long)]
    pub no_passphrase: bool,

    /// Read the new key's passphrase from the first line of stdin
    #[arg(long)]
    pub passphrase_stdin: bool,

    /// Load the new key into ssh-agent as soon as it exists
    #[arg(short = 'a', long)]
    pub add: bool,

    /// Don't load the new key into ssh-agent, even if add_to_agent is set
    #[arg(long, conflicts_with = "add")]
    pub no_add: bool,

    /// Extra ssh option for every ssh call, passed through as -o (repeatable)
    #[arg(short = 'o', long = "ssh-option", value_name = "K=V", action = clap::ArgAction::Append)]
    pub ssh_option: Vec<String>,
}

pub fn new_name(name: &str) -> String {
    format!("{name}.new")
}

pub fn old_name(name: &str) -> String {
    format!("{name}.old")
}

fn target_of(d: &Deployment) -> Target {
    Target {
        user: d.user.clone(),
        host: d.host.clone(),
        port: Some(d.port),
    }
}

/// Step 2: put `new` on every deployment, logging in with `old`. Every host is
/// attempted; the caller decides what a failure means.
pub fn install_everywhere(
    runner: &dyn SshRunner,
    ui: &Ui,
    old: &Identity,
    new: &Identity,
    deployments: &[Deployment],
    ssh_options: &[String],
) -> anyhow::Result<Vec<(Deployment, copy::Outcome)>> {
    let public_line = new.public_key_line()?;
    let opts = CopyOptions {
        ssh_options: ssh_options.to_vec(),
        auth_key: Some(old.private_path.clone()),
        // The install snippet is idempotent, so always run it: the probe then only has to
        // answer "does the new key work now", never "may I skip the install".
        force: true,
        ..Default::default()
    };
    let mut out = Vec::new();
    for d in deployments {
        let target = target_of(d);
        let outcome = copy::copy_one(runner, ui, new, &target, &opts, &public_line)
            .with_context(|| format!("{target}: running ssh"))?;
        out.push((d.clone(), outcome));
    }
    Ok(out)
}

/// Step 3: remove `old` from every deployment, logging in with `new`.
pub fn revoke_everywhere(
    runner: &dyn SshRunner,
    ui: &Ui,
    old: &Identity,
    new: &Identity,
    deployments: &[Deployment],
    ssh_options: &[String],
) -> anyhow::Result<Vec<(Deployment, revoke_cmd::Outcome)>> {
    let public_line = old.public_key_line()?;
    let mut out = Vec::new();
    for d in deployments {
        let target = target_of(d);
        let outcome = revoke_cmd::revoke_one(
            runner,
            ui,
            old,
            &new.private_path,
            &target,
            ssh_options,
            &public_line,
        )
        .with_context(|| format!("{target}: running ssh"))?;
        out.push((d.clone(), outcome));
    }
    Ok(out)
}

/// Step 4: `<name>` -> `<name>.old`, `<name>.new` -> `<name>`; `created` and every
/// `installed` become `now`. `lingering` are deployments where the old key is still
/// accepted: then the `.old` pair is kept and recorded under `<name>.old`; otherwise it
/// is deleted.
pub fn swap(ssh_dir: &Path, name: &str, lingering: &[Deployment], now: &str) -> anyhow::Result<()> {
    let path = |n: &str| ssh_dir.join(n);
    let pub_path = |n: &str| ssh_dir.join(format!("{n}.pub"));
    let (new_n, old_n) = (new_name(name), old_name(name));

    // Validate everything before touching a single file: once the renames start, the old
    // key may already be revoked from every host, so there is no going back.
    let mut st = State::load(ssh_dir)?;
    if !path(&new_n).is_file() || !pub_path(&new_n).is_file() {
        bail!("{new_n} and {new_n}.pub must both exist to swap");
    }

    let mv = |from: &Path, to: &Path| {
        fs::rename(from, to)
            .with_context(|| format!("renaming {} -> {}", from.display(), to.display()))
    };
    mv(&path(name), &path(&old_n))?;
    if pub_path(name).is_file() {
        mv(&pub_path(name), &pub_path(&old_n))?;
    }
    mv(&path(&new_n), &path(name))?;
    mv(&pub_path(&new_n), &pub_path(name))?;

    st.identity.remove(&new_n);
    let previous_created = st.identity.get(name).and_then(|e| e.created.clone());
    {
        let entry = st.identity.entry(name.to_string()).or_default();
        entry.created = Some(now.to_string());
        for d in &mut entry.deployments {
            d.installed = now.to_string();
        }
    }
    if lingering.is_empty() {
        fs::remove_file(path(&old_n))
            .with_context(|| format!("removing {}", path(&old_n).display()))?;
        // A leftover <name>.old.pub would trip the `.old` guard on the next rotation with
        // a misleading "a previous rotation left work.old behind", so say so now.
        if pub_path(&old_n).is_file() {
            fs::remove_file(pub_path(&old_n))
                .with_context(|| format!("removing {}", pub_path(&old_n).display()))?;
        }
        st.identity.remove(&old_n);
    } else {
        let entry = st.identity.entry(old_n).or_default();
        entry.created = previous_created;
        entry.deployments = lingering.to_vec();
    }
    st.save(ssh_dir)?;
    Ok(())
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Rotate) -> anyhow::Result<u8> {
    let dir = &settings.ssh_dir;
    let old = store::resolve(dir, &args.identity)?;
    old.public_key_line()?;
    let name = old.name.clone();
    let st = State::load(dir)?;
    let deployments = st.deployments(&name).to_vec();
    let new_n = new_name(&name);
    let resume = dir.join(&new_n).is_file();

    // A previous rotation may have left `<name>.old` behind (a revoke that never
    // finished): swap would clobber that file and lose the record of where it still
    // lives, so refuse until it is cleaned up.
    let old_n = old_name(&name);
    if dir.join(&old_n).exists()
        || dir.join(format!("{old_n}.pub")).exists()
        || st.is_managed(&old_n)
    {
        bail!(
            "a previous rotation left {old_n} behind (it may still be installed somewhere); finish that first: ssk revoke {old_n} --all && ssk rm {old_n}"
        );
    }

    // What the new key will be.
    let key_type = args.key_type.unwrap_or(match old.algorithm.as_str() {
        "rsa" => KeyType::Rsa,
        "ecdsa" => KeyType::Ecdsa,
        _ => KeyType::Ed25519,
    });
    let inherited = if args.key_type.is_none() && key_type != KeyType::Ed25519 {
        old.bits
    } else {
        None
    };
    // `-t rsa` without `-b` gets the configured size, exactly as `ssk new` does.
    let requested = args
        .bits
        .or(inherited)
        .or((key_type == KeyType::Rsa).then_some(settings.rsa_bits));
    let bits = match keygen::resolve_bits(key_type, requested) {
        Ok(b) => b,
        Err(_) if args.bits.is_none() && inherited.is_some() => {
            // e.g. rsa 1024: that size is no longer allowed, so use the configured default.
            let fallback = (key_type == KeyType::Rsa).then_some(settings.rsa_bits);
            let bits = keygen::resolve_bits(key_type, fallback)?;
            ui.warn(format!(
                "current key is {}; the new key will be {} {}",
                old.type_label(),
                key_type.as_str(),
                bits.unwrap_or_default()
            ));
            bits
        }
        Err(e) => return Err(e.into()),
    };
    if old.algorithm == "dsa" && args.key_type.is_none() {
        ui.warn("current key is dsa; the new key will be ed25519");
    }
    let comment_text = args.comment.clone().unwrap_or_else(|| {
        if old.comment.is_empty() {
            comment::render(&settings.comment_template, &name)
        } else {
            old.comment.clone()
        }
    });
    let add = !args.no_add && (args.add || settings.add_to_agent);
    let type_label = match bits {
        Some(b) => format!("{} {b}", key_type.as_str()),
        None => key_type.as_str().to_string(),
    };

    // The plan.
    ui.info(format!("rotate '{name}':"));
    if resume {
        ui.info(format!(
            "  1. reuse the existing {new_n} (an earlier rotation was interrupted)"
        ));
    } else {
        ui.info(format!("  1. generate a new {type_label} key as {new_n}"));
    }
    if deployments.is_empty() {
        ui.warn(
            "no deployments recorded; only the local key changes. Anything that holds the old public key (GitHub, other hosts) must be updated by hand.",
        );
    } else {
        let hosts: Vec<String> = deployments.iter().map(|d| d.endpoint()).collect();
        ui.info(format!(
            "  2. install it on {} host{} ({}), logging in with the current key",
            hosts.len(),
            if hosts.len() == 1 { "" } else { "s" },
            hosts.join(", ")
        ));
        ui.info(
            "  3. once every host accepts the new key, remove the current key from all of them",
        );
    }
    ui.info(format!(
        "  4. replace {} with the new key; delete the old one",
        old.private_path.display()
    ));
    if settings.dry_run {
        describe_dry_run(ui, dir, &old, &deployments, &args.ssh_option);
        return Ok(0);
    }
    if !ui.confirm("Continue?")? {
        return Ok(1);
    }

    // 1. the new key
    if !resume {
        let passphrase = new::read_passphrase(
            ui,
            args.passphrase.as_deref(),
            args.no_passphrase,
            args.passphrase_stdin,
        )?;
        if passphrase.is_none() {
            ui.warn("creating the new key without a passphrase");
        }
        let key = keygen::generate(
            &KeySpec {
                key_type,
                bits,
                comment: comment_text,
            },
            passphrase.as_deref().map(|p| p.as_str()),
        )?;
        keygen::write_pair(dir, &new_n, &key, false)?;
    }
    let new = Identity::load(dir, &new_n)
        .with_context(|| format!("{new_n} exists but cannot be loaded; remove it to start over"))?;
    ui.success(format!("{new_n}: {} {}", new.type_label(), new.fingerprint));
    let agent_status = agent::status();
    let in_agent = |id: &Identity| agent::contains(&agent_status, &id.fingerprint) == Some(true);
    if add {
        if agent_status == agent::AgentStatus::Unavailable {
            ui.warn("no ssh-agent is available; --add ignored");
        } else if !in_agent(&new) {
            agent::add(&new.private_path, ui).context("adding the new key to ssh-agent")?;
        }
    } else if new.encrypted && !in_agent(&new) && !deployments.is_empty() {
        ui.warn(format!(
            "{new_n} is passphrase-protected and not in ssh-agent; ssh will ask for its passphrase for each host. --add loads it once."
        ));
    }
    if old.encrypted && !in_agent(&old) && !deployments.is_empty() {
        ui.warn(format!(
            "'{name}' is passphrase-protected and not in ssh-agent; ssh will ask for its passphrase for each host. `ssk add {name}` first avoids that."
        ));
    }

    let runner = copy::runner_for(settings)?.expect("dry-run returned earlier");
    // 2. install everywhere
    let installs = install_everywhere(
        runner.as_ref(),
        ui,
        &old,
        &new,
        &deployments,
        &args.ssh_option,
    )?;
    let mut blocked = false;
    for (d, outcome) in &installs {
        let at = d.endpoint();
        match outcome {
            copy::Outcome::AlreadyInstalled => {
                ui.success(format!("{at}: new key already installed"))
            }
            copy::Outcome::Installed => ui.success(format!("{at}: new key installed and verified")),
            copy::Outcome::InstalledUnverified => {
                blocked = true;
                ui.error(format!(
                    "{at}: new key installed, but it does not authenticate yet"
                ));
            }
            copy::Outcome::Unreachable(m) => {
                blocked = true;
                ui.error(format!("{at}: could not connect: {m}"));
            }
            copy::Outcome::Failed(m) => {
                blocked = true;
                ui.error(format!("{at}: install failed: {m}"));
            }
            copy::Outcome::DryRun => {}
        }
    }
    if blocked {
        ui.error(format!(
            "not rotated: the new key is not accepted everywhere yet. Both keys are kept; '{name}' is still the live one."
        ));
        ui.hint(format!(
            "fix the hosts above, then re-run `ssk rotate {name}` to resume with {new_n}"
        ));
        return Ok(1);
    }

    // 3. revoke the old key everywhere
    let revokes = revoke_everywhere(
        runner.as_ref(),
        ui,
        &old,
        &new,
        &deployments,
        &args.ssh_option,
    )?;
    let mut lingering = Vec::new();
    for (d, outcome) in &revokes {
        let at = d.endpoint();
        match outcome {
            revoke_cmd::Outcome::Revoked => {
                ui.success(format!("{at}: old key removed and verified"))
            }
            revoke_cmd::Outcome::NotPresent => ui.success(format!("{at}: old key was not present")),
            revoke_cmd::Outcome::RevokedUnverified(m) => ui.warn(format!(
                "{at}: old key removed, but verification could not connect: {m}"
            )),
            other => {
                lingering.push(d.clone());
                ui.error(format!(
                    "{at}: old key still accepted ({})",
                    revoke_cmd::describe(other)
                ));
            }
        }
    }

    // 4. swap. ssh-add -d needs the old .pub, so it goes before the swap; whether a
    // failure matters is only known afterwards (agent::still_loaded).
    let agent_failure = in_agent(&old)
        .then(|| agent::delete(&old.private_path, ui).err())
        .flatten();
    swap(dir, &name, &lingering, &state::now())?;
    if let Some(e) = agent_failure
        && agent::still_loaded(&old.fingerprint)
    {
        ui.warn(format!(
            "could not remove the old key from ssh-agent: {e:#}"
        ));
    }
    let rotated = Identity::load(dir, &name)?;
    ui.success(format!("rotated identity {name}"));
    ui.info(format!("  type         {}", rotated.type_label()));
    ui.info(format!("  fingerprint  {}", rotated.fingerprint));
    ui.info("");
    ui.info(rotated.public_key_line()?);
    ui.info("");
    if lingering.is_empty() {
        ui.hint("anything outside ssk.toml that holds the old public key (GitHub, a cloud console) needs the line above");
        Ok(0)
    } else {
        let hosts: Vec<String> = lingering.iter().map(|d| d.endpoint()).collect();
        ui.warn(format!(
            "old key kept as {old_n}; still accepted on {}.",
            hosts.join(", ")
        ));
        ui.hint(format!("ssk revoke {old_n} --all && ssk rm {old_n}"));
        Ok(1)
    }
}

fn describe_dry_run(
    ui: &Ui,
    ssh_dir: &Path,
    old: &Identity,
    deployments: &[Deployment],
    ssh_options: &[String],
) {
    let new_key = ssh_dir.join(new_name(&old.name));
    let new_line = format!("<{}.pub>", new_key.display());
    let old_line = old.public_key_line().unwrap_or_default();
    for d in deployments {
        let target = target_of(d);
        ui.info(format!("{target}: would run"));
        let probe_new = probe::invocation(&new_key, &target, ssh_options);
        let install_new =
            install::invocation(&target, ssh_options, &new_line, Some(&old.private_path));
        let revoke_old = revoke::invocation(&new_key, &target, ssh_options, &old_line);
        let probe_old = probe::invocation(&old.private_path, &target, ssh_options);
        ui.info(format!("  ssh {}", shell_join(&probe_new.args)));
        ui.info(format!(
            "  ssh {}   (new public key on stdin)",
            shell_join(&install_new.args)
        ));
        ui.info(format!("  ssh {}", shell_join(&probe_new.args)));
        ui.info(format!(
            "  ssh {}   (old public key on stdin)",
            shell_join(&revoke_old.args)
        ));
        ui.info(format!("  ssh {}", shell_join(&probe_old.args)));
    }
    ui.info(format!(
        "then: {} -> {}, {} -> {}, update {}",
        old.private_path.display(),
        ssh_dir.join(old_name(&old.name)).display(),
        new_key.display(),
        old.private_path.display(),
        State::path(ssh_dir).display()
    ));
    ui.info("dry run: nothing generated, installed or removed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keygen::{KeySpec, KeyType, generate, write_pair};
    use crate::ssh::runner::SshOutput;
    use crate::ssh::runner::fake::{FakeSsh, accepts, denied, ok, unreachable};

    fn make(dir: &Path, name: &str) -> Identity {
        let key = generate(
            &KeySpec {
                key_type: KeyType::Ed25519,
                bits: None,
                comment: format!("{name}@box"),
            },
            None,
        )
        .unwrap();
        write_pair(dir, name, &key, false).unwrap();
        Identity::load(dir, name).unwrap()
    }

    fn fixture() -> (tempfile::TempDir, Identity, Identity) {
        let tmp = tempfile::tempdir().unwrap();
        let old = make(tmp.path(), "work");
        let new = make(tmp.path(), "work.new");
        (tmp, old, new)
    }

    fn dep(host: &str) -> Deployment {
        Deployment {
            host: host.into(),
            user: Some("deploy".into()),
            port: 22,
            alias: host.into(),
            installed: "t0".into(),
        }
    }

    fn has(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn install_everywhere_probes_with_new_and_authenticates_with_old() {
        let (_tmp, old, new) = fixture();
        // Forced, so every host is probe -> install -> verify: three calls each.
        let ssh = FakeSsh::new(vec![
            denied(),
            ok(),
            accepts(&new.private_path),
            accepts(&new.private_path),
            ok(),
            accepts(&new.private_path),
        ]);
        let out = install_everywhere(&ssh, &Ui::silent(), &old, &new, &[dep("a"), dep("b")], &[])
            .unwrap();
        assert_eq!(out[0].1, copy::Outcome::Installed);
        assert_eq!(out[1].1, copy::Outcome::Installed);
        let calls = ssh.calls();
        assert_eq!(calls.len(), 6);
        let new_p = new.private_path.display().to_string();
        let old_p = old.private_path.display().to_string();
        for probe in [0, 2, 3, 5] {
            assert!(
                has(&calls[probe].args, "-i", &new_p),
                "call {probe} probes with the new key"
            );
        }
        for install in [1, 4] {
            assert!(
                has(&calls[install].args, "-i", &old_p),
                "call {install} authenticates with the old key"
            );
            assert!(
                calls[install]
                    .args
                    .iter()
                    .any(|a| a == "IdentitiesOnly=yes"),
                "call {install} must not let ssh spray agent keys"
            );
            assert_eq!(
                calls[install].stdin.as_deref(),
                Some(format!("{}\n", new.public_key_line().unwrap()).as_str())
            );
        }
    }

    #[test]
    fn install_everywhere_keeps_going_after_a_failure() {
        let (_tmp, old, new) = fixture();
        let ssh = FakeSsh::new(vec![unreachable(), ok(), ok(), accepts(&new.private_path)]);
        let out = install_everywhere(&ssh, &Ui::silent(), &old, &new, &[dep("a"), dep("b")], &[])
            .unwrap();
        assert!(matches!(out[0].1, copy::Outcome::Unreachable(_)));
        assert_eq!(out[1].1, copy::Outcome::Installed);
    }

    #[test]
    fn revoke_everywhere_authenticates_with_new_and_verifies_old() {
        let (_tmp, old, new) = fixture();
        let not_present = SshOutput {
            code: Some(3),
            ..Default::default()
        };
        let ssh = FakeSsh::new(vec![ok(), denied(), not_present, denied()]);
        let out =
            revoke_everywhere(&ssh, &Ui::silent(), &old, &new, &[dep("a"), dep("b")], &[]).unwrap();
        assert_eq!(out[0].1, revoke_cmd::Outcome::Revoked);
        assert_eq!(out[1].1, revoke_cmd::Outcome::NotPresent);
        let calls = ssh.calls();
        assert!(has(
            &calls[0].args,
            "-i",
            &new.private_path.display().to_string()
        ));
        assert_eq!(
            calls[0].stdin.as_deref(),
            Some(format!("{}\n", old.public_key_line().unwrap()).as_str())
        );
        assert!(has(
            &calls[1].args,
            "-i",
            &old.private_path.display().to_string()
        ));
    }

    #[test]
    fn swap_replaces_files_and_updates_state() {
        let (tmp, old, new) = fixture();
        let d = tmp.path();
        let mut st = State::default();
        st.record_created("work", "t-created".into());
        st.record_deployment("work", dep("a"));
        st.save(d).unwrap();

        swap(d, "work", &[], "NOW").unwrap();
        let rotated = Identity::load(d, "work").unwrap();
        assert_eq!(rotated.fingerprint, new.fingerprint);
        assert_ne!(rotated.fingerprint, old.fingerprint);
        assert!(!d.join("work.new").exists() && !d.join("work.new.pub").exists());
        assert!(!d.join("work.old").exists() && !d.join("work.old.pub").exists());
        let st = State::load(d).unwrap();
        assert_eq!(st.identity["work"].created.as_deref(), Some("NOW"));
        assert_eq!(st.deployments("work")[0].installed, "NOW");
        assert!(!st.is_managed("work.old") && !st.is_managed("work.new"));
    }

    #[test]
    fn swap_keeps_and_records_the_old_key_when_it_lingers() {
        let (tmp, old, _new) = fixture();
        let d = tmp.path();
        let mut st = State::default();
        st.record_created("work", "t-created".into());
        st.record_deployment("work", dep("a"));
        st.record_deployment("work", dep("b"));
        st.save(d).unwrap();

        swap(d, "work", &[dep("b")], "NOW").unwrap();
        let kept = Identity::load(d, "work.old").unwrap();
        assert_eq!(kept.fingerprint, old.fingerprint);
        assert!(d.join("work.old.pub").exists());
        let st = State::load(d).unwrap();
        assert_eq!(
            st.deployments("work").len(),
            2,
            "the new key is on both hosts"
        );
        assert_eq!(st.deployments("work.old").len(), 1);
        assert_eq!(st.deployments("work.old")[0].host, "b");
        assert_eq!(
            st.identity["work.old"].created.as_deref(),
            Some("t-created")
        );
    }

    #[test]
    fn swap_refuses_when_the_new_pub_is_missing() {
        let (tmp, _old, _new) = fixture();
        let d = tmp.path();
        fs::remove_file(d.join("work.new.pub")).unwrap();

        assert!(swap(d, "work", &[], "NOW").is_err());
        assert!(d.join("work").exists());
        assert!(d.join("work.pub").exists());
        assert!(d.join("work.new").exists());
    }

    #[test]
    fn swap_refuses_on_unreadable_state_before_touching_files() {
        let (tmp, _old, _new) = fixture();
        let d = tmp.path();
        fs::write(d.join("ssk.toml"), "this is = not [toml").unwrap();

        assert!(swap(d, "work", &[], "NOW").is_err());
        assert!(d.join("work").exists());
        assert!(d.join("work.new").exists());
    }
}
