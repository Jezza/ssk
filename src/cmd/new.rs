//! `ssk new <IDENTITY>`: generate a key pair, write it, record it, show the public key.

use std::io::{self, IsTerminal};
use std::path::Path;

use anyhow::{Context, bail};
use zeroize::Zeroizing;

use crate::cmd::copy::{self, CopyOptions};
use crate::identity::keygen::{self, KeySpec, KeyType};
use crate::identity::{Identity, comment, name};
use crate::settings::Settings;
use crate::ssh::{agent, config};
use crate::state::{self, State};
use crate::target::Target;
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
#[command(group = clap::ArgGroup::new("pass").args(["passphrase", "no_passphrase", "passphrase_stdin"]))]
pub struct New {
    /// Identity name; becomes the filename under the ssh directory
    pub identity: String,

    /// Key comment [default: {identity}@{hostname}]
    #[arg(short = 'c', long, visible_short_alias = 'C', value_name = "TEXT")]
    pub comment: Option<String>,

    /// Key type [default: ed25519, or default_type from the config file]
    #[arg(
        short = 't',
        long = "type",
        alias = "algo",
        value_enum,
        value_name = "ALGO"
    )]
    pub key_type: Option<KeyType>,

    /// Key size. rsa: 2048|3072|4096 (default 4096). ecdsa: 256|384|521 (default 256). Not valid for ed25519
    #[arg(short = 'b', long, value_name = "N")]
    pub bits: Option<u32>,

    /// Set the passphrase non-interactively. Visible in `ps` and shell history; scripts only
    #[arg(short = 'N', long, value_name = "TEXT")]
    pub passphrase: Option<String>,

    /// Create the key without a passphrase
    #[arg(long)]
    pub no_passphrase: bool,

    /// Read the passphrase from the first line of stdin
    #[arg(long)]
    pub passphrase_stdin: bool,

    /// Load the new key into ssh-agent
    #[arg(short = 'l', long)]
    pub load: bool,

    /// Don't load the key into ssh-agent, even if add_to_agent is set in the config file
    #[arg(long, conflicts_with = "load")]
    pub no_load: bool,

    /// Overwrite an existing identity of the same name
    #[arg(short = 'f', long)]
    pub force: bool,

    /// After creating, install the key on TARGET ([user@]host[:port]) and write ssh config
    /// for it; repeatable
    #[arg(long, value_name = "TARGET", action = clap::ArgAction::Append)]
    pub copy: Vec<String>,

    /// Extra ssh option for --copy, passed through as -o (repeatable), e.g. ProxyJump=bastion
    #[arg(short = 'o', long = "ssh-option", value_name = "K=V", action = clap::ArgAction::Append, requires = "copy")]
    pub ssh_option: Vec<String>,

    /// Host alias to write into ssh config for the --copy target [default: the identity
    /// name, so `ssh <IDENTITY>` reaches it; with several targets, each host as typed]
    #[arg(long, value_name = "NAME", requires = "copy")]
    pub alias: Option<String>,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &New) -> anyhow::Result<u8> {
    name::validate(&args.identity)?;
    if let Some(alias) = &args.alias {
        config::validate_alias(alias)?;
        if args.copy.len() != 1 {
            bail!(
                "--alias applies to exactly one target; got {} --copy targets",
                args.copy.len()
            );
        }
    }
    let targets = copy::parse_targets(&args.copy, None, None)?;
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

    let key_type = args.key_type.unwrap_or(settings.default_type);
    let default_bits = (key_type == KeyType::Rsa).then_some(settings.rsa_bits);
    let bits = keygen::resolve_bits(key_type, args.bits.or(default_bits))?;
    let comment = args
        .comment
        .clone()
        .unwrap_or_else(|| comment::render(&settings.comment_template, &args.identity));
    let passphrase = read_passphrase(
        ui,
        args.passphrase.as_deref(),
        args.no_passphrase,
        args.passphrase_stdin,
    )?;

    if settings.dry_run {
        ui.info(format!(
            "would generate {}{} key '{}' with comment '{}' at {} ({})",
            key_type.as_str(),
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
        key_type,
        bits,
        comment,
    };
    let key = keygen::generate(&spec, passphrase.as_deref().map(|p| p.as_str()))?;
    let written = keygen::write_pair(&settings.ssh_dir, &args.identity, &key, args.force)?;

    let mut st = State::load(&settings.ssh_dir)?;
    st.record_created(&args.identity, state::now());
    st.save(&settings.ssh_dir)?;

    let add_to_agent = !args.no_load && (args.load || settings.add_to_agent);
    if add_to_agent {
        agent::add(&written.private_path, ui)
            .context("the key was created, but adding it to ssh-agent failed")?;
    }

    let identity = Identity::load(&settings.ssh_dir, &args.identity)?;
    let public_line = identity.public_key_line()?;
    print_summary(ui, "created", &identity, &public_line);

    if !targets.is_empty() {
        ui.info("");
        let alias = match (&args.alias, targets.as_slice()) {
            (Some(a), _) => Some(a.clone()),
            (None, [target]) => default_alias(ui, &settings.ssh_dir, &st, &args.identity, target)?,
            (None, _) => None,
        };
        let runner = copy::runner_for(settings)?;
        return copy::run_targets(
            settings,
            ui,
            &identity,
            &targets,
            &CopyOptions {
                ssh_options: args.ssh_option.clone(),
                alias,
                write_config: settings.write_ssh_config,
                ..Default::default()
            },
            runner.as_deref(),
        );
    }
    Ok(0)
}

/// A key made for one host gets a `Host` block named after itself, so `ssh <identity>`
/// just works. `None` (the host as typed, as `copy` does) when that would clash or
/// would not work: the name is already another deployment's block (ssh only ever reads
/// the first), or a `Host` line of the user's own config applies to one of the two
/// names but not the other, so `ssh <identity>` would hijack their block or lose the
/// settings `ssh <host>` gets. A record of this identity on the same endpoint does not
/// count, as the copy replaces it.
fn default_alias(
    ui: &Ui,
    ssh_dir: &Path,
    st: &State,
    identity: &str,
    target: &Target,
) -> anyhow::Result<Option<String>> {
    let host = &target.host;
    if host == identity {
        return Ok(None);
    }
    let replaced = |n: &str, d: &state::Deployment| {
        n == identity
            && d.host == *host
            && d.user == target.user
            && d.port == target.port.unwrap_or(22)
    };
    if let Some((n, _, d)) = st.aliased(identity).find(|(n, _, d)| !replaced(n, d)) {
        ui.warn(format!(
            "'{identity}' is already the alias of {n}: {}; using '{host}' instead (`ssk alias` can change it)",
            d.endpoint()
        ));
        return Ok(None);
    }
    let lines = config::user_host_lines(ssh_dir)?;
    if let Some(l) = lines
        .iter()
        .find(|l| l.applies_to(identity) && !l.applies_to(host))
    {
        ui.warn(format!(
            "'{identity}' is already a Host in {}; using '{host}' instead (`ssk alias` can change it)",
            l.file.display()
        ));
        return Ok(None);
    }
    if let Some(l) = lines
        .iter()
        .find(|l| l.applies_to(host) && !l.applies_to(identity))
    {
        ui.info(format!(
            "'{host}' is a Host in {}; keeping that name so its settings still apply",
            l.file.display()
        ));
        return Ok(None);
    }
    Ok(Some(identity.to_string()))
}

/// `None` means no passphrase. Precedence: `none`, `explicit`, `from_stdin`, prompt.
pub fn read_passphrase(
    ui: &Ui,
    explicit: Option<&str>,
    none: bool,
    from_stdin: bool,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    if none {
        return Ok(None);
    }
    if let Some(p) = explicit {
        return Ok(non_empty(p));
    }
    if from_stdin {
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

/// `verb` is what happened: `created identity work`, `imported identity work`.
pub fn print_summary(ui: &Ui, verb: &str, identity: &Identity, public_line: &str) {
    ui.success(format!("{verb} identity {}", identity.name));
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
