//! Command-line surface: the global flags and the subcommand list. Each subcommand's own
//! arguments live beside its handler in `cmd/`.

use std::path::PathBuf;

use crate::cmd::*;

#[derive(clap::Parser, Debug)]
#[command(
    name = "ssk",
    version,
    about = "Manage SSH identities: generate keys, install them on hosts, keep track of both."
)]
pub struct Args {
    #[command(flatten)]
    pub ctx: Ctx,

    #[command(subcommand)]
    pub command: Command,
}

/// Flags every subcommand accepts.
#[derive(clap::Parser, Debug, Default, Clone)]
pub struct Ctx {
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
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// When to colour output
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto, value_name = "WHEN")]
    pub color: ColorChoice,

    /// Machine-readable JSON on stdout (list, show, doctor, hosts, config get)
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Generate a new key pair
    New(new::New),
    /// Install an identity's public key on one or more hosts
    Copy(copy::Copy),
    /// Show all identities
    #[command(alias = "ls")]
    List(list::List),
    /// Show one identity in detail
    Show(show::Show),
    /// Find (and fix) hygiene problems in the ssh directory
    #[command(alias = "doc")]
    Doctor(doctor::Doctor),
    /// Load identities into ssh-agent
    Add(add::Add),
    /// Delete an identity from this machine
    #[command(alias = "rm", alias = "remove")]
    Delete(delete::Delete),
    /// Rename an identity; state and generated ssh config follow
    Rename(rename::Rename),
    /// Remove an identity's public key from hosts
    Revoke(revoke::Revoke),
    /// Read or write ~/.config/ssk/config.toml
    Config(config::Config),
    /// Replace an identity's key: install the new key everywhere, revoke the old one, swap
    Rotate(rotate::Rotate),
    /// Host x identity deployment matrix
    Hosts(hosts::Hosts),
    /// Print a shell completion script
    Completions(completions::Completions),
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::New(_) => "new",
            Command::Copy(_) => "copy",
            Command::List(_) => "list",
            Command::Show(_) => "show",
            Command::Doctor(_) => "doctor",
            Command::Add(_) => "add",
            Command::Delete(_) => "delete",
            Command::Rename(_) => "rename",
            Command::Revoke(_) => "revoke",
            Command::Config(_) => "config",
            Command::Rotate(_) => "rotate",
            Command::Hosts(_) => "hosts",
            Command::Completions(_) => "completions",
        }
    }

    /// Commands whose output has a documented JSON form.
    pub fn supports_json(&self) -> bool {
        matches!(
            self,
            Command::List(_)
                | Command::Show(_)
                | Command::Doctor(_)
                | Command::Hosts(_)
                | Command::Config(config::Config {
                    cmd: config::Cmd::Get(_)
                })
        )
    }
}
