//! Command-line surface. Pure clap derive types; no behaviour lives here.

use std::path::PathBuf;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::identity::keygen::KeyType;

#[derive(Parser, Debug)]
#[command(
    name = "ssk",
    version,
    about = "Manage SSH identities: generate keys, install them on hosts, keep track of both."
)]
pub struct Cli {
    /// SSH directory to manage
    #[arg(long, global = true, env = "SSK_SSH_DIR", value_name = "DIR")]
    pub ssh_dir: Option<PathBuf>,

    /// Assume yes on confirmations
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,

    /// Print what would happen; touch nothing, locally or remotely
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Errors only
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Show the ssh / ssh-add commands being run (-vv also passes -v to ssh)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// When to colour output
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto, value_name = "WHEN")]
    pub color: ColorChoice,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a new key pair
    New(NewArgs),
    /// Install an identity's public key on one or more hosts
    Copy(CopyArgs),
    /// Show all identities
    #[command(alias = "ls")]
    List,
    /// Show one identity in detail
    Show(ShowArgs),
    /// Find (and fix) hygiene problems in the ssh directory
    Doctor(DoctorArgs),
    /// Print a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::New(_) => "new",
            Command::Copy(_) => "copy",
            Command::List => "list",
            Command::Show(_) => "show",
            Command::Doctor(_) => "doctor",
            Command::Completions { .. } => "completions",
        }
    }
}

#[derive(Args, Debug)]
#[command(group = ArgGroup::new("pass").args(["passphrase", "no_passphrase", "passphrase_stdin"]))]
pub struct NewArgs {
    /// Identity name; becomes the filename under the ssh directory
    pub identity: String,

    /// Key comment [default: {identity}@{hostname}]
    #[arg(short = 'c', long, visible_short_alias = 'C', value_name = "TEXT")]
    pub comment: Option<String>,

    /// Key type
    #[arg(short = 't', long = "type", alias = "algo", value_enum, default_value_t = KeyType::Ed25519, value_name = "ALGO")]
    pub key_type: KeyType,

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

    /// Add the new key to ssh-agent
    #[arg(short = 'a', long)]
    pub add: bool,

    /// Overwrite an existing identity of the same name
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct CopyArgs {
    /// Identity whose public key to install
    pub identity: String,

    /// [user@]host[:port], or a Host alias from your ssh config
    #[arg(required = true, value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Default port for targets that don't specify one
    #[arg(short = 'p', long, value_name = "N")]
    pub port: Option<u16>,

    /// Default user for targets that don't specify one
    #[arg(short = 'l', long, value_name = "USER")]
    pub login: Option<String>,

    /// Extra ssh option, passed through as -o (repeatable), e.g. ProxyJump=bastion
    #[arg(short = 'o', long = "ssh-option", value_name = "K=V", action = ArgAction::Append)]
    pub ssh_option: Vec<String>,

    /// Host alias to write into ssh config (default: the host as typed). Needs exactly one target
    #[arg(long, value_name = "NAME")]
    pub alias: Option<String>,

    /// Don't write a Host block to ssh config
    #[arg(long)]
    pub no_config: bool,

    /// Install even if the key already authenticates
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Identity to show
    pub identity: String,

    /// Print only the public key line
    #[arg(short = 'p', long = "pub")]
    pub pub_only: bool,

    /// Print only the SHA256 fingerprint
    #[arg(long, conflicts_with = "pub_only")]
    pub fingerprint: bool,
}

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Apply the safe fixes (tighten permissions, regenerate .pub, add the Include line)
    #[arg(long)]
    pub fix: bool,
}
