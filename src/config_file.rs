//! `~/.config/ssk/config.toml`: user preferences. Loading is strict (an unknown key
//! is an error); writing goes through `toml_edit` so the user's comments survive.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::fsx;
use crate::identity::keygen::{self, KeyType};

pub const KEYS: &[&str] = &[
    "ssh_dir",
    "default_type",
    "rsa_bits",
    "comment",
    "add_to_agent",
    "write_ssh_config",
];

/// Written by `ssk config edit` when the file does not exist yet.
pub const TEMPLATE: &str = "\
# ssk configuration. Every key is optional. Flags and SSK_* environment variables
# override what is set here.
#
# ssh_dir = \"~/.ssh\"
# default_type = \"ed25519\"            # ed25519 | rsa | ecdsa
# rsa_bits = 4096                      # 2048 | 3072 | 4096
# comment = \"{identity}@{hostname}\"   # variables: {identity} {hostname} {user}
# add_to_agent = false                 # `ssk new` runs ssh-add afterwards
# write_ssh_config = true              # `ssk copy` writes ssk.d/<identity>.conf and the Include line
";

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub ssh_dir: Option<String>,
    pub default_type: Option<String>,
    pub rsa_bits: Option<u32>,
    pub comment: Option<String>,
    pub add_to_agent: Option<bool>,
    pub write_ssh_config: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{}: {message}", .path.display())]
    Parse { path: PathBuf, message: String },
    #[error("cannot write {}: {source}", .path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "unknown config key '{0}'; known keys: ssh_dir, default_type, rsa_bits, comment, add_to_agent, write_ssh_config"
    )]
    UnknownKey(String),
    #[error("{key}: {message}")]
    Invalid { key: &'static str, message: String },
}

/// `$SSK_CONFIG`, else `$XDG_CONFIG_HOME/ssk/config.toml`, else `~/.config/ssk/config.toml`.
pub fn path() -> Option<PathBuf> {
    path_with(
        std::env::var_os("SSK_CONFIG").as_deref(),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        crate::settings::home_dir().as_deref(),
    )
}

pub fn path_with(
    explicit: Option<&OsStr>,
    xdg: Option<&OsStr>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(p) = explicit.filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    if let Some(x) = xdg.filter(|x| !x.is_empty()) {
        return Some(PathBuf::from(x).join("ssk").join("config.toml"));
    }
    home.map(|h| h.join(".config").join("ssk").join("config.toml"))
}

/// A missing file is an empty one.
pub fn load(path: &Path) -> Result<FileConfig, ConfigError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(FileConfig::default()),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    parse(&text).map_err(|message| ConfigError::Parse {
        path: path.to_path_buf(),
        message,
    })
}

/// Parse and validate. The error is a message without a path; `load` adds it.
pub fn parse(text: &str) -> Result<FileConfig, String> {
    let cfg: FileConfig = toml::from_str(text).map_err(|e| e.to_string().trim().to_string())?;
    validate(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg)
}

pub fn validate(cfg: &FileConfig) -> Result<(), ConfigError> {
    if let Some(t) = &cfg.default_type {
        parse_key_type(t)?;
    }
    if let Some(b) = cfg.rsa_bits {
        check_rsa_bits(b)?;
    }
    if let Some(c) = &cfg.comment {
        check_comment(c)?;
    }
    Ok(())
}

pub fn parse_key_type(s: &str) -> Result<KeyType, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "ed25519" => Ok(KeyType::Ed25519),
        "rsa" => Ok(KeyType::Rsa),
        "ecdsa" => Ok(KeyType::Ecdsa),
        other => Err(ConfigError::Invalid {
            key: "default_type",
            message: format!("'{other}' is not one of ed25519, rsa, ecdsa"),
        }),
    }
}

pub fn check_rsa_bits(bits: u32) -> Result<u32, ConfigError> {
    if keygen::RSA_ALLOWED.contains(&bits) {
        Ok(bits)
    } else {
        Err(ConfigError::Invalid {
            key: "rsa_bits",
            message: format!("{bits} is not one of 2048, 3072, 4096"),
        })
    }
}

/// Every `{...}` must be a known variable; anything else is almost certainly a typo.
pub fn check_comment(template: &str) -> Result<(), ConfigError> {
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else { break };
        let var = &after[..end];
        if !matches!(var, "identity" | "hostname" | "user") {
            return Err(ConfigError::Invalid {
                key: "comment",
                message: format!(
                    "unknown variable {{{var}}}; known: {{identity}} {{hostname}} {{user}}"
                ),
            });
        }
        rest = &after[end + 1..];
    }
    Ok(())
}

pub fn parse_bool(s: &str, key: &'static str) -> Result<bool, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(ConfigError::Invalid {
            key,
            message: format!("'{other}' is not a boolean (true/false)"),
        }),
    }
}

/// `~` and `~/rest` expand against `home`; everything else passes through unchanged.
pub fn expand_tilde(raw: &str, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return PathBuf::from(raw);
    };
    if raw == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest);
    }
    PathBuf::from(raw)
}

/// `~/x` and relative paths are taken against `home`; absolute paths pass through.
pub fn expand_dir(raw: &str, home: Option<&Path>) -> PathBuf {
    if raw.starts_with('~') {
        return expand_tilde(raw, home);
    }
    let Some(home) = home else {
        return PathBuf::from(raw);
    };
    let p = PathBuf::from(raw);
    if p.is_relative() { home.join(p) } else { p }
}

/// Validate `value` for `key`, then write it, leaving every other byte of the file alone.
pub fn set(path: &Path, key: &str, value: &str) -> Result<(), ConfigError> {
    let item = typed_item(key, value)?;
    let mut doc = read_doc(path)?;
    doc[key] = item;
    write_doc(path, &doc)
}

/// Remove `key`. `Ok(false)` when it was not there.
pub fn unset(path: &Path, key: &str) -> Result<bool, ConfigError> {
    if !KEYS.contains(&key) {
        return Err(ConfigError::UnknownKey(key.to_string()));
    }
    let mut doc = read_doc(path)?;
    let existed = doc.remove(key).is_some();
    if existed {
        write_doc(path, &doc)?;
    }
    Ok(existed)
}

fn typed_item(key: &str, value: &str) -> Result<toml_edit::Item, ConfigError> {
    Ok(match key {
        "ssh_dir" => toml_edit::value(value),
        "default_type" => toml_edit::value(parse_key_type(value)?.as_str()),
        "rsa_bits" => {
            let bits: u32 = value.trim().parse().map_err(|_| ConfigError::Invalid {
                key: "rsa_bits",
                message: format!("'{value}' is not a number"),
            })?;
            toml_edit::value(i64::from(check_rsa_bits(bits)?))
        }
        "comment" => {
            check_comment(value)?;
            toml_edit::value(value)
        }
        "add_to_agent" => toml_edit::value(parse_bool(value, "add_to_agent")?),
        "write_ssh_config" => toml_edit::value(parse_bool(value, "write_ssh_config")?),
        other => return Err(ConfigError::UnknownKey(other.to_string())),
    })
}

fn read_doc(path: &Path) -> Result<toml_edit::DocumentMut, ConfigError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    text.parse::<toml_edit::DocumentMut>()
        .map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
}

fn write_doc(path: &Path, doc: &toml_edit::DocumentMut) -> Result<(), ConfigError> {
    let text = doc.to_string();
    // The whole file must still load; never persist something `load` would reject.
    parse(&text).map_err(|message| ConfigError::Parse {
        path: path.to_path_buf(),
        message,
    })?;
    write_text(path, &text)
}

/// Create the directory (0700) if needed and write the file atomically at 0600.
pub fn write_text(path: &Path, text: &str) -> Result<(), ConfigError> {
    let wrap = |source| ConfigError::Write {
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent() {
        fsx::ensure_private_dir(dir).map_err(wrap)?;
    }
    fsx::write_private(path, text.as_bytes()).map_err(wrap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::Path;

    #[test]
    fn path_precedence_is_explicit_then_xdg_then_home() {
        let e = OsStr::new("/e/c.toml");
        let x = OsStr::new("/x");
        let h = Path::new("/h");
        assert_eq!(
            path_with(Some(e), Some(x), Some(h)),
            Some(PathBuf::from("/e/c.toml"))
        );
        assert_eq!(
            path_with(None, Some(x), Some(h)),
            Some(PathBuf::from("/x/ssk/config.toml"))
        );
        assert_eq!(
            path_with(None, None, Some(h)),
            Some(PathBuf::from("/h/.config/ssk/config.toml"))
        );
        assert_eq!(
            path_with(Some(OsStr::new("")), None, Some(h)),
            Some(PathBuf::from("/h/.config/ssk/config.toml"))
        );
        assert_eq!(path_with(None, None, None), None);
    }

    #[test]
    fn parses_every_key_and_the_empty_file() {
        assert_eq!(parse("").unwrap(), FileConfig::default());
        let cfg = parse(
            "ssh_dir = \"~/.ssh\"\ndefault_type = \"rsa\"\nrsa_bits = 3072\ncomment = \"{user}@{hostname}\"\nadd_to_agent = true\nwrite_ssh_config = false\n",
        )
        .unwrap();
        assert_eq!(cfg.ssh_dir.as_deref(), Some("~/.ssh"));
        assert_eq!(cfg.default_type.as_deref(), Some("rsa"));
        assert_eq!(cfg.rsa_bits, Some(3072));
        assert_eq!(cfg.comment.as_deref(), Some("{user}@{hostname}"));
        assert_eq!(cfg.add_to_agent, Some(true));
        assert_eq!(cfg.write_ssh_config, Some(false));
        assert_eq!(
            parse(TEMPLATE).unwrap(),
            FileConfig::default(),
            "the template is all comments"
        );
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        let e = parse("ssh-dir = \"/x\"\n").unwrap_err();
        assert!(e.contains("ssh-dir"), "{e}");
        let e = parse("default_type = \"dsa\"\n").unwrap_err();
        assert!(e.contains("default_type") && e.contains("dsa"), "{e}");
        let e = parse("rsa_bits = 1024\n").unwrap_err();
        assert!(e.contains("rsa_bits") && e.contains("1024"), "{e}");
        let e = parse("comment = \"{nope}\"\n").unwrap_err();
        assert!(e.contains("comment") && e.contains("{nope}"), "{e}");
        let e = parse("add_to_agent = \"yes\"\n").unwrap_err();
        assert!(e.contains("add_to_agent"), "{e}");
    }

    #[test]
    fn value_parsers() {
        assert_eq!(parse_key_type("RSA").unwrap(), KeyType::Rsa);
        assert!(parse_key_type("x").is_err());
        assert_eq!(check_rsa_bits(4096).unwrap(), 4096);
        assert!(check_rsa_bits(4095).is_err());
        assert!(check_comment("{identity}@{hostname} {user}").is_ok());
        assert!(check_comment("plain").is_ok());
        assert!(check_comment("{host}").is_err());
        for (s, v) in [
            ("true", true),
            ("1", true),
            ("yes", true),
            ("on", true),
            ("false", false),
            ("0", false),
            ("no", false),
            ("off", false),
            (" No ", false),
        ] {
            assert_eq!(parse_bool(s, "k").unwrap(), v, "{s}");
        }
        assert!(parse_bool("maybe", "k").is_err());
    }

    #[test]
    fn expand_dir_handles_tilde_and_relative() {
        let h = Some(Path::new("/home/j"));
        assert_eq!(expand_dir("~/.ssh", h), PathBuf::from("/home/j/.ssh"));
        assert_eq!(expand_dir("~", h), PathBuf::from("/home/j"));
        assert_eq!(expand_dir("keys", h), PathBuf::from("/home/j/keys"));
        assert_eq!(expand_dir("/srv/keys", h), PathBuf::from("/srv/keys"));
        assert_eq!(expand_dir("~/.ssh", None), PathBuf::from("~/.ssh"));
    }

    #[test]
    fn expand_tilde_only_touches_leading_tilde() {
        let h = Some(Path::new("/home/j"));
        assert_eq!(expand_tilde("~/.ssh", h), PathBuf::from("/home/j/.ssh"));
        assert_eq!(expand_tilde("~", h), PathBuf::from("/home/j"));
        assert_eq!(expand_tilde("keys", h), PathBuf::from("keys"));
        assert_eq!(expand_tilde("~/.ssh", None), PathBuf::from("~/.ssh"));
    }

    #[test]
    fn load_missing_is_default_and_garbage_names_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("config.toml");
        assert_eq!(load(&p).unwrap(), FileConfig::default());
        std::fs::write(&p, "this = [is not toml").unwrap();
        let e = load(&p).unwrap_err().to_string();
        assert!(e.contains("config.toml"), "{e}");
    }

    #[test]
    fn set_creates_and_types_values_and_keeps_comments() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("sub").join("config.toml");
        set(&p, "default_type", "Rsa").unwrap();
        assert_eq!(crate::fsx::mode_of(&p).unwrap(), 0o600);
        assert_eq!(crate::fsx::mode_of(p.parent().unwrap()).unwrap(), 0o700);
        std::fs::write(&p, "# mine\ndefault_type = \"rsa\" # keep\n").unwrap();
        set(&p, "rsa_bits", "2048").unwrap();
        set(&p, "add_to_agent", "yes").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("# mine") && text.contains("# keep"), "{text}");
        assert!(text.contains("rsa_bits = 2048"), "{text}");
        assert!(text.contains("add_to_agent = true"), "{text}");
        assert_eq!(load(&p).unwrap().rsa_bits, Some(2048));

        let before = text.clone();
        assert!(set(&p, "rsa_bits", "1234").is_err());
        assert!(set(&p, "nope", "1").is_err());
        assert!(matches!(
            set(&p, "nope", "1"),
            Err(ConfigError::UnknownKey(_))
        ));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);

        assert!(unset(&p, "rsa_bits").unwrap());
        assert!(!unset(&p, "rsa_bits").unwrap());
        assert!(!std::fs::read_to_string(&p).unwrap().contains("rsa_bits"));
        assert!(matches!(unset(&p, "nope"), Err(ConfigError::UnknownKey(_))));
    }
}
