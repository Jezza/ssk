//! Effective settings: flags, `SSK_*` environment variables, the config file and
//! built-in defaults merged into one struct, remembering where each value came from.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context;
use serde::Serialize;

use crate::args::{ColorChoice, Ctx};
use crate::config_file::{self, FileConfig};
use crate::identity::keygen::{self, KeyType};

pub const DEFAULT_COMMENT_TEMPLATE: &str = "{identity}@{hostname}";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Flag,
    Env,
    File,
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Env => "env",
            Source::File => "file",
            Source::Default => "default",
        }
    }
}

/// `SSK_*` variables, parsed. `None` means unset or empty.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnvConfig {
    pub ssh_dir: Option<PathBuf>,
    pub default_type: Option<KeyType>,
    pub rsa_bits: Option<u32>,
    pub comment: Option<String>,
    pub add_to_agent: Option<bool>,
    pub write_ssh_config: Option<bool>,
}

impl EnvConfig {
    pub fn from_env() -> anyhow::Result<EnvConfig> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<EnvConfig> {
        let get = |k: &str| get(k).filter(|v| !v.is_empty());
        let mut e = EnvConfig {
            ssh_dir: get("SSK_SSH_DIR").map(PathBuf::from),
            ..Default::default()
        };
        if let Some(v) = get("SSK_DEFAULT_TYPE") {
            e.default_type = Some(
                config_file::parse_key_type(&v).context("environment variable SSK_DEFAULT_TYPE")?,
            );
        }
        if let Some(v) = get("SSK_RSA_BITS") {
            let bits: u32 = v.trim().parse().with_context(|| {
                format!("environment variable SSK_RSA_BITS: '{v}' is not a number")
            })?;
            e.rsa_bits = Some(
                config_file::check_rsa_bits(bits).context("environment variable SSK_RSA_BITS")?,
            );
        }
        if let Some(v) = get("SSK_COMMENT") {
            config_file::check_comment(&v).context("environment variable SSK_COMMENT")?;
            e.comment = Some(v);
        }
        if let Some(v) = get("SSK_ADD_TO_AGENT") {
            e.add_to_agent = Some(
                config_file::parse_bool(&v, "add_to_agent")
                    .context("environment variable SSK_ADD_TO_AGENT")?,
            );
        }
        if let Some(v) = get("SSK_WRITE_SSH_CONFIG") {
            e.write_ssh_config = Some(
                config_file::parse_bool(&v, "write_ssh_config")
                    .context("environment variable SSK_WRITE_SSH_CONFIG")?,
            );
        }
        Ok(e)
    }
}

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
    pub default_type: KeyType,
    pub rsa_bits: u32,
    pub add_to_agent: bool,
    pub write_ssh_config: bool,
    /// Where the config file is, or would be. `None` only without a home directory.
    pub config_path: Option<PathBuf>,
    /// Where each of the six config keys got its value.
    pub sources: BTreeMap<&'static str, Source>,
}

impl Settings {
    pub fn from_ctx(ctx: &Ctx) -> anyhow::Result<Self> {
        let (settings, problem) = Self::load(ctx)?;
        match problem {
            Some(err) => Err(err),
            None => Ok(settings),
        }
    }

    /// `from_ctx`, except that a config file which cannot be read or parsed is *reported*
    /// rather than fatal: the settings come back built on defaults for the file's keys,
    /// with the error beside them. `ssk config path|edit|set|unset` use this, so a broken
    /// config file can still be repaired with ssk itself.
    pub fn from_ctx_lenient(ctx: &Ctx) -> anyhow::Result<(Self, Option<anyhow::Error>)> {
        Self::load(ctx)
    }

    fn load(ctx: &Ctx) -> anyhow::Result<(Self, Option<anyhow::Error>)> {
        let config_path = config_file::path();
        let (file, problem) = match &config_path {
            Some(p) => match config_file::load(p) {
                Ok(f) => (f, None),
                Err(e) => (FileConfig::default(), Some(anyhow::Error::new(e))),
            },
            None => (FileConfig::default(), None),
        };
        let env = EnvConfig::from_env()?;
        Ok((
            Self::resolve(ctx, &env, &file, config_path, home_dir())?,
            problem,
        ))
    }

    /// flag > env > file > default, per key. clap has already merged `SSK_SSH_DIR` into
    /// `ctx.ssh_dir`; `env.ssh_dir` tells us whether that is where it came from.
    pub fn resolve(
        ctx: &Ctx,
        env: &EnvConfig,
        file: &FileConfig,
        config_path: Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let mut sources = BTreeMap::new();
        let ssh_dir = match (&ctx.ssh_dir, &file.ssh_dir) {
            (Some(d), _) => {
                let src = if env.ssh_dir.as_ref() == Some(d) {
                    Source::Env
                } else {
                    Source::Flag
                };
                sources.insert("ssh_dir", src);
                config_file::expand_tilde(&d.to_string_lossy(), home.as_deref())
            }
            (None, Some(f)) => {
                sources.insert("ssh_dir", Source::File);
                config_file::expand_dir(f, home.as_deref())
            }
            (None, None) => {
                sources.insert("ssh_dir", Source::Default);
                home.as_deref()
                    .map(|h| h.join(".ssh"))
                    .context("cannot determine your home directory")?
            }
        };
        let file_type = file
            .default_type
            .as_deref()
            .map(config_file::parse_key_type)
            .transpose()?;
        let default_type = pick(
            &mut sources,
            "default_type",
            env.default_type,
            file_type,
            KeyType::Ed25519,
        );
        let rsa_bits = pick(
            &mut sources,
            "rsa_bits",
            env.rsa_bits,
            file.rsa_bits,
            keygen::RSA_DEFAULT,
        );
        let comment_template = pick(
            &mut sources,
            "comment",
            env.comment.clone(),
            file.comment.clone(),
            DEFAULT_COMMENT_TEMPLATE.to_string(),
        );
        let add_to_agent = pick(
            &mut sources,
            "add_to_agent",
            env.add_to_agent,
            file.add_to_agent,
            false,
        );
        let write_ssh_config = pick(
            &mut sources,
            "write_ssh_config",
            env.write_ssh_config,
            file.write_ssh_config,
            true,
        );
        Ok(Settings {
            ssh_dir,
            yes: ctx.yes,
            dry_run: ctx.dry_run,
            quiet: ctx.quiet,
            verbose: ctx.verbose,
            color: ctx.color,
            json: ctx.json,
            comment_template,
            default_type,
            rsa_bits,
            add_to_agent,
            write_ssh_config,
            config_path,
            sources,
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
            default_type: KeyType::Ed25519,
            rsa_bits: keygen::RSA_DEFAULT,
            add_to_agent: false,
            write_ssh_config: true,
            config_path: None,
            sources: BTreeMap::new(),
        }
    }
}

fn pick<T>(
    sources: &mut BTreeMap<&'static str, Source>,
    key: &'static str,
    env: Option<T>,
    file: Option<T>,
    default: T,
) -> T {
    let (value, source) = match (env, file) {
        (Some(e), _) => (e, Source::Env),
        (None, Some(f)) => (f, Source::File),
        (None, None) => (default, Source::Default),
    };
    sources.insert(key, source);
    value
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
    use crate::args::Args;
    use clap::Parser;

    fn parse(args: &[&str]) -> Ctx {
        Args::try_parse_from(std::iter::once("ssk").chain(args.iter().copied()))
            .unwrap()
            .ctx
    }

    fn resolve(args: &[&str], env: EnvConfig, file: FileConfig) -> Settings {
        Settings::resolve(
            &parse(args),
            &env,
            &file,
            None,
            Some(PathBuf::from("/home/j")),
        )
        .unwrap()
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        let s = resolve(&["list"], EnvConfig::default(), FileConfig::default());
        assert_eq!(s.ssh_dir, PathBuf::from("/home/j/.ssh"));
        assert_eq!(s.default_type, KeyType::Ed25519);
        assert_eq!(s.rsa_bits, 4096);
        assert_eq!(s.comment_template, DEFAULT_COMMENT_TEMPLATE);
        assert!(!s.add_to_agent && s.write_ssh_config);
        assert!(s.sources.values().all(|v| *v == Source::Default));
        assert_eq!(s.sources.len(), 6);
    }

    #[test]
    fn file_beats_default_and_env_beats_file() {
        let file = FileConfig {
            ssh_dir: Some("~/keys".into()),
            default_type: Some("rsa".into()),
            rsa_bits: Some(2048),
            comment: Some("{user}".into()),
            add_to_agent: Some(true),
            write_ssh_config: Some(false),
        };
        let s = resolve(&["list"], EnvConfig::default(), file.clone());
        assert_eq!(s.ssh_dir, PathBuf::from("/home/j/keys"));
        assert_eq!(s.default_type, KeyType::Rsa);
        assert_eq!(s.rsa_bits, 2048);
        assert_eq!(s.comment_template, "{user}");
        assert!(s.add_to_agent && !s.write_ssh_config);
        assert!(s.sources.values().all(|v| *v == Source::File));

        let env = EnvConfig {
            default_type: Some(KeyType::Ecdsa),
            rsa_bits: Some(3072),
            ..Default::default()
        };
        let s = resolve(&["list"], env, file);
        assert_eq!(s.default_type, KeyType::Ecdsa);
        assert_eq!(s.rsa_bits, 3072);
        assert_eq!(s.sources["default_type"], Source::Env);
        assert_eq!(s.sources["rsa_bits"], Source::Env);
        assert_eq!(s.sources["comment"], Source::File);
    }

    #[test]
    fn ssh_dir_flag_and_env_are_told_apart() {
        let s = resolve(
            &["--ssh-dir", "/tmp/a", "list"],
            EnvConfig::default(),
            FileConfig::default(),
        );
        assert_eq!(s.ssh_dir, PathBuf::from("/tmp/a"));
        assert_eq!(s.sources["ssh_dir"], Source::Flag);
        let env = EnvConfig {
            ssh_dir: Some(PathBuf::from("/tmp/a")),
            ..Default::default()
        };
        let s = resolve(&["--ssh-dir", "/tmp/a", "list"], env, FileConfig::default());
        assert_eq!(s.sources["ssh_dir"], Source::Env);
    }

    #[test]
    fn ssh_dir_flag_and_env_expand_tilde_but_not_relative_paths() {
        let s = resolve(
            &["--ssh-dir", "~/keys", "list"],
            EnvConfig::default(),
            FileConfig::default(),
        );
        assert_eq!(s.ssh_dir, PathBuf::from("/home/j/keys"));
        assert_eq!(s.sources["ssh_dir"], Source::Flag);

        let env = EnvConfig {
            ssh_dir: Some(PathBuf::from("~/keys")),
            ..Default::default()
        };
        let s = resolve(&["--ssh-dir", "~/keys", "list"], env, FileConfig::default());
        assert_eq!(s.ssh_dir, PathBuf::from("/home/j/keys"));
        assert_eq!(s.sources["ssh_dir"], Source::Env);

        let s = resolve(
            &["--ssh-dir", "rel/keys", "list"],
            EnvConfig::default(),
            FileConfig::default(),
        );
        assert_eq!(s.ssh_dir, PathBuf::from("rel/keys"));
    }

    #[test]
    fn env_lookup_parses_and_names_bad_variables() {
        let vars = |k: &str| match k {
            "SSK_DEFAULT_TYPE" => Some("rsa".to_string()),
            "SSK_RSA_BITS" => Some("3072".to_string()),
            "SSK_COMMENT" => Some("{identity}".to_string()),
            "SSK_ADD_TO_AGENT" => Some("1".to_string()),
            "SSK_WRITE_SSH_CONFIG" => Some("no".to_string()),
            "SSK_SSH_DIR" => Some("".to_string()),
            _ => None,
        };
        let e = EnvConfig::from_lookup(vars).unwrap();
        assert_eq!(e.default_type, Some(KeyType::Rsa));
        assert_eq!(e.rsa_bits, Some(3072));
        assert_eq!(e.comment.as_deref(), Some("{identity}"));
        assert_eq!(e.add_to_agent, Some(true));
        assert_eq!(e.write_ssh_config, Some(false));
        assert_eq!(e.ssh_dir, None, "empty means unset");

        let bad = |k: &str| (k == "SSK_RSA_BITS").then(|| "17".to_string());
        let err = EnvConfig::from_lookup(bad).unwrap_err().to_string();
        assert!(err.contains("SSK_RSA_BITS"), "{err}");
    }

    #[test]
    fn verbosity_counts_and_quiet_is_exclusive() {
        let s = resolve(
            &["-vv", "list"],
            EnvConfig::default(),
            FileConfig::default(),
        );
        assert_eq!(s.verbose, 2);
        assert!(Args::try_parse_from(["ssk", "-q", "-v", "list"]).is_err());
    }

    #[test]
    fn for_dir_is_quiet_and_assumes_yes() {
        let s = Settings::for_dir("/x");
        assert!(s.quiet && s.yes && !s.dry_run && !s.json);
        assert_eq!(s.comment_template, DEFAULT_COMMENT_TEMPLATE);
        assert_eq!(s.default_type, KeyType::Ed25519);
    }
}
