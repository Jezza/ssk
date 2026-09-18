//! Effective settings: CLI flags and environment merged with built-in defaults.
//! (Phase 2 adds `~/.config/ssk/config.toml` between env and defaults.)

use std::path::PathBuf;

use anyhow::Context;

use crate::cli::{Cli, ColorChoice};

pub const DEFAULT_COMMENT_TEMPLATE: &str = "{identity}@{hostname}";

#[derive(Debug, Clone)]
pub struct Settings {
    pub ssh_dir: PathBuf,
    pub yes: bool,
    pub dry_run: bool,
    pub quiet: bool,
    pub verbose: u8,
    pub color: ColorChoice,
    pub json: bool,
    pub comment_template: String,
}

impl Settings {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let ssh_dir = match &cli.ssh_dir {
            Some(dir) => dir.clone(),
            None => default_ssh_dir()?,
        };
        Ok(Settings {
            ssh_dir,
            yes: cli.yes,
            dry_run: cli.dry_run,
            quiet: cli.quiet,
            verbose: cli.verbose,
            color: cli.color,
            json: cli.json,
            comment_template: DEFAULT_COMMENT_TEMPLATE.to_string(),
        })
    }

    /// Settings for library-level tests: quiet, non-interactive, pointed at `ssh_dir`.
    pub fn for_dir(ssh_dir: impl Into<PathBuf>) -> Self {
        Settings {
            ssh_dir: ssh_dir.into(),
            yes: true,
            dry_run: false,
            quiet: true,
            verbose: 0,
            color: ColorChoice::Never,
            json: false,
            comment_template: DEFAULT_COMMENT_TEMPLATE.to_string(),
        }
    }
}

pub fn home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

pub fn default_ssh_dir() -> anyhow::Result<PathBuf> {
    Ok(home_dir()
        .context("cannot determine your home directory")?
        .join(".ssh"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("ssk").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn ssh_dir_defaults_to_home_dot_ssh() {
        let s = Settings::from_cli(&parse(&["list"])).unwrap();
        assert!(s.ssh_dir.ends_with(".ssh"), "{}", s.ssh_dir.display());
    }

    #[test]
    fn ssh_dir_flag_overrides_default() {
        let s = Settings::from_cli(&parse(&["--ssh-dir", "/tmp/somewhere", "list"])).unwrap();
        assert_eq!(s.ssh_dir, PathBuf::from("/tmp/somewhere"));
    }

    #[test]
    fn verbosity_counts_and_quiet_is_exclusive() {
        let s = Settings::from_cli(&parse(&["-vv", "list"])).unwrap();
        assert_eq!(s.verbose, 2);
        assert!(Cli::try_parse_from(["ssk", "-q", "-v", "list"]).is_err());
    }

    #[test]
    fn for_dir_is_quiet_and_assumes_yes() {
        let s = Settings::for_dir("/x");
        assert!(s.quiet && s.yes && !s.dry_run);
        assert_eq!(s.comment_template, DEFAULT_COMMENT_TEMPLATE);
    }
}
