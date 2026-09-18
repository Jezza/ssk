//! `ssk new <IDENTITY>`: generate a key pair, write it, record it, show the public key.

use std::io::{self, IsTerminal};

use anyhow::{Context, bail};
use zeroize::Zeroizing;

use crate::cli::NewArgs;
use crate::commands::copy::{self, CopyOptions};
use crate::identity::keygen::{self, KeySpec};
use crate::identity::{Identity, comment, name};
use crate::settings::Settings;
use crate::ssh::agent;
use crate::state::{self, State};
use crate::ui::Ui;

pub fn run(settings: &Settings, ui: &Ui, args: &NewArgs) -> anyhow::Result<u8> {
    name::validate(&args.identity)?;
    let private_path = settings.ssh_dir.join(&args.identity);
    let public_path = settings.ssh_dir.join(format!("{}.pub", args.identity));
    if private_path.exists() || public_path.exists() {
        if !args.force {
            bail!(
                "identity '{}' already exists at {} (use --force to overwrite)",
                args.identity,
                private_path.display()
            );
        }
        if !ui.confirm(&format!(
            "Overwrite identity '{}'? The old key is not kept",
            args.identity
        ))? {
            return Ok(1);
        }
    }

    let bits = keygen::resolve_bits(args.key_type, args.bits)?;
    let comment = args
        .comment
        .clone()
        .unwrap_or_else(|| comment::render(&settings.comment_template, &args.identity));
    let passphrase = read_passphrase(ui, args)?;

    if settings.dry_run {
        ui.info(format!(
            "would generate {}{} key '{}' with comment '{}' at {} ({})",
            args.key_type.as_str(),
            bits.map(|b| format!("-{b}")).unwrap_or_default(),
            args.identity,
            comment,
            private_path.display(),
            if passphrase.is_some() {
                "passphrase-protected"
            } else {
                "no passphrase"
            },
        ));
        return Ok(0);
    }
    if passphrase.is_none() {
        ui.warn("creating the key without a passphrase");
    }

    let spec = KeySpec {
        key_type: args.key_type,
        bits,
        comment,
    };
    let key = keygen::generate(&spec, passphrase.as_deref().map(|p| p.as_str()))?;
    let written = keygen::write_pair(&settings.ssh_dir, &args.identity, &key, args.force)?;

    let mut st = State::load(&settings.ssh_dir)?;
    st.record_created(&args.identity, state::now());
    st.save(&settings.ssh_dir)?;

    if args.add {
        agent::add(&written.private_path, ui)
            .context("the key was created, but adding it to ssh-agent failed")?;
    }

    let identity = Identity::load(&settings.ssh_dir, &args.identity)?;
    let public_line = identity.public_key_line()?;
    print_summary(ui, &identity, &public_line);

    if !args.copy.is_empty() {
        ui.info("");
        let targets = copy::parse_targets(&args.copy, None, None)?;
        let runner = copy::runner_for(settings)?;
        return copy::run_targets(
            settings,
            ui,
            &identity,
            &targets,
            &CopyOptions::default(),
            runner.as_deref(),
        );
    }
    Ok(0)
}

/// `None` means no passphrase. Precedence: --no-passphrase, -N, --passphrase-stdin, prompt.
fn read_passphrase(ui: &Ui, args: &NewArgs) -> anyhow::Result<Option<Zeroizing<String>>> {
    if args.no_passphrase {
        return Ok(None);
    }
    if let Some(p) = &args.passphrase {
        return Ok(non_empty(p));
    }
    if args.passphrase_stdin {
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("reading the passphrase from stdin")?;
        return Ok(non_empty(line.trim_end_matches(['\r', '\n'])));
    }
    if !io::stdin().is_terminal() {
        bail!(
            "no terminal to prompt for a passphrase; pass --no-passphrase, --passphrase-stdin or -N"
        );
    }
    let p = ui.password(
        "Enter passphrase (empty for no passphrase)",
        Some(("Enter same passphrase again", "Passphrases do not match")),
    )?;
    Ok(non_empty(&p))
}

fn non_empty(p: &str) -> Option<Zeroizing<String>> {
    (!p.is_empty()).then(|| Zeroizing::new(p.to_string()))
}

fn print_summary(ui: &Ui, identity: &Identity, public_line: &str) {
    ui.success(format!("created identity {}", identity.name));
    ui.info(format!("  type         {}", identity.type_label()));
    ui.info(format!("  fingerprint  {}", identity.fingerprint));
    ui.info(format!(
        "  private      {}  (mode 0600, passphrase: {})",
        identity.private_path.display(),
        if identity.encrypted { "yes" } else { "no" }
    ));
    if let Some(p) = &identity.public_path {
        ui.info(format!("  public       {}", p.display()));
    }
    ui.info("");
    ui.info(public_line);
    ui.info("");
    ui.hint(format!(
        "ssk copy {} user@host   (or paste the public key above into GitHub, GitLab, ...)",
        identity.name
    ));
}
