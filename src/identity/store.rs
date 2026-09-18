//! Discover identities by scanning the ssh dir; resolve a name to one.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::name::{self, NameError};
use super::{Identity, IdentityError};

#[derive(Debug)]
pub enum Entry {
    Identity(Identity),
    /// A private-key-looking file that didn't load.
    Broken {
        name: String,
        path: PathBuf,
        error: IdentityError,
    },
    /// A `.pub` with no private half.
    OrphanPublic {
        name: String,
        path: PathBuf,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("{0}")]
    InvalidName(#[from] NameError),
    #[error("no identity named '{name}' in {}{}", .dir.display(), did_you_mean(.suggestion))]
    NotFound {
        name: String,
        dir: PathBuf,
        suggestion: Option<String>,
    },
    #[error(transparent)]
    Load(#[from] IdentityError),
}

fn did_you_mean(s: &Option<String>) -> String {
    match s {
        Some(s) => format!("; did you mean '{s}'?"),
        None => String::new(),
    }
}

/// Names of files in `ssh_dir` that look like private keys and are valid identity names.
pub fn private_key_names(ssh_dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    if !ssh_dir.is_dir() {
        return Ok(names);
    }
    for entry in fs::read_dir(ssh_dir)? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if fname.ends_with(".pub") || name::validate(fname).is_err() {
            continue;
        }
        if looks_like_private_key(&path) {
            names.push(fname.to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn looks_like_private_key(path: &Path) -> bool {
    let mut head = [0u8; 11];
    fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .map(|n| &head[..n] == b"-----BEGIN ")
        .unwrap_or(false)
}

/// Everything in the ssh dir that is or should be an identity. Identities first
/// (by name), then broken files, then orphan `.pub`s.
pub fn scan(ssh_dir: &Path) -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    if !ssh_dir.is_dir() {
        return Ok(out);
    }
    let privates: BTreeSet<String> = private_key_names(ssh_dir)?.into_iter().collect();
    let mut publics = BTreeSet::new();
    for entry in fs::read_dir(ssh_dir)? {
        let path = entry?.path();
        if let Some(stem) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".pub"))
            && path.is_file()
        {
            publics.insert(stem.to_string());
        }
    }
    let mut broken = Vec::new();
    for name in &privates {
        match Identity::load(ssh_dir, name) {
            Ok(id) => out.push(Entry::Identity(id)),
            Err(error) => broken.push(Entry::Broken {
                name: name.clone(),
                path: ssh_dir.join(name),
                error,
            }),
        }
    }
    out.extend(broken);
    for stem in publics.difference(&privates) {
        out.push(Entry::OrphanPublic {
            name: stem.clone(),
            path: ssh_dir.join(format!("{stem}.pub")),
        });
    }
    Ok(out)
}

/// Best close match for a mistyped name, if any is close enough.
pub fn suggest(name: &str, candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .map(|c| (strsim::normalized_damerau_levenshtein(name, c), c))
        .filter(|(score, _)| *score >= 0.6)
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .map(|(_, c)| c.clone())
}

pub fn resolve(ssh_dir: &Path, name: &str) -> Result<Identity, ResolveError> {
    name::validate(name)?;
    if !ssh_dir.join(name).is_file() {
        let candidates = private_key_names(ssh_dir).unwrap_or_default();
        return Err(ResolveError::NotFound {
            name: name.to_string(),
            dir: ssh_dir.to_path_buf(),
            suggestion: suggest(name, &candidates),
        });
    }
    Ok(Identity::load(ssh_dir, name)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keygen::{KeySpec, KeyType, generate, write_pair};

    fn make(ssh_dir: &Path, name: &str) {
        let key = generate(
            &KeySpec {
                key_type: KeyType::Ed25519,
                bits: None,
                comment: name.into(),
            },
            None,
        )
        .unwrap();
        write_pair(ssh_dir, name, &key, false).unwrap();
    }

    fn populated() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        make(d, "work");
        make(d, "github");
        std::fs::write(
            d.join("old"),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(d.join("orphan.pub"), "ssh-ed25519 AAAA orphan\n").unwrap();
        std::fs::write(d.join("config"), "Host *\n").unwrap();
        std::fs::write(d.join("known_hosts"), "").unwrap();
        std::fs::write(d.join("notes.txt"), "not a key\n").unwrap();
        std::fs::create_dir(d.join("alt")).unwrap();
        tmp
    }

    #[test]
    fn scan_classifies_everything() {
        let tmp = populated();
        let entries = scan(tmp.path()).unwrap();
        let names: Vec<String> = entries
            .iter()
            .map(|e| match e {
                Entry::Identity(id) => format!("id:{}", id.name),
                Entry::Broken { name, .. } => format!("broken:{name}"),
                Entry::OrphanPublic { name, .. } => format!("orphan:{name}"),
            })
            .collect();
        assert_eq!(
            names,
            vec!["id:github", "id:work", "broken:old", "orphan:orphan"]
        );
    }

    #[test]
    fn scan_of_missing_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(scan(&tmp.path().join("nope")).unwrap().is_empty());
    }

    #[test]
    fn resolve_finds_loads_and_suggests() {
        let tmp = populated();
        assert_eq!(resolve(tmp.path(), "work").unwrap().name, "work");
        match resolve(tmp.path(), "githb") {
            Err(ResolveError::NotFound { suggestion, .. }) => {
                assert_eq!(suggestion.as_deref(), Some("github"))
            }
            other => panic!("{other:?}"),
        }
        let msg = resolve(tmp.path(), "githb").unwrap_err().to_string();
        assert!(msg.contains("did you mean 'github'"), "{msg}");
        assert!(matches!(
            resolve(tmp.path(), "config"),
            Err(ResolveError::InvalidName(_))
        ));
        assert!(matches!(
            resolve(tmp.path(), "old"),
            Err(ResolveError::Load(IdentityError::LegacyPem { .. }))
        ));
    }

    #[test]
    fn suggest_needs_a_close_match() {
        let c = vec!["github".to_string(), "work".to_string()];
        assert_eq!(suggest("githb", &c).as_deref(), Some("github"));
        assert_eq!(suggest("zzzzzz", &c), None);
    }
}
