//! In-process key generation with the `ssh-key` crate. Output is byte-compatible
//! with `ssh-keygen`: OpenSSH private key format, aes256-ctr + bcrypt-pbkdf/16 when
//! a passphrase is given.

use std::io;
use std::path::{Path, PathBuf};

use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::rand_core::OsRng;
use ssh_key::{EcdsaCurve, LineEnding, PrivateKey};

use crate::fsx;

/// Key algorithms ssk can generate.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Rsa,
    Ecdsa,
}

impl KeyType {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Rsa => "rsa",
            KeyType::Ecdsa => "ecdsa",
        }
    }
}

pub const RSA_ALLOWED: &[u32] = &[2048, 3072, 4096];
pub const RSA_DEFAULT: u32 = 4096;
pub const ECDSA_ALLOWED: &[u32] = &[256, 384, 521];
pub const ECDSA_DEFAULT: u32 = 256;

#[derive(Debug, Clone)]
pub struct KeySpec {
    pub key_type: KeyType,
    pub bits: Option<u32>,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub struct Written {
    pub private_path: PathBuf,
    pub public_path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("--bits is not applicable to ed25519 keys")]
    BitsNotApplicable,
    #[error("invalid size {bits} for {key_type}; allowed: {allowed}")]
    InvalidBits {
        key_type: &'static str,
        bits: u32,
        allowed: &'static str,
    },
    #[error("{} already exists (use --force to overwrite)", .0.display())]
    Exists(PathBuf),
    #[error("key generation failed: {0}")]
    Key(#[from] ssh_key::Error),
    #[error("cannot write {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Apply per-type defaults and validate. `Ok(None)` for ed25519.
pub fn resolve_bits(key_type: KeyType, bits: Option<u32>) -> Result<Option<u32>, KeygenError> {
    match (key_type, bits) {
        (KeyType::Ed25519, None) => Ok(None),
        (KeyType::Ed25519, Some(_)) => Err(KeygenError::BitsNotApplicable),
        (KeyType::Rsa, None) => Ok(Some(RSA_DEFAULT)),
        (KeyType::Rsa, Some(b)) if RSA_ALLOWED.contains(&b) => Ok(Some(b)),
        (KeyType::Rsa, Some(b)) => Err(KeygenError::InvalidBits {
            key_type: "rsa",
            bits: b,
            allowed: "2048, 3072, 4096",
        }),
        (KeyType::Ecdsa, None) => Ok(Some(ECDSA_DEFAULT)),
        (KeyType::Ecdsa, Some(b)) if ECDSA_ALLOWED.contains(&b) => Ok(Some(b)),
        (KeyType::Ecdsa, Some(b)) => Err(KeygenError::InvalidBits {
            key_type: "ecdsa",
            bits: b,
            allowed: "256, 384, 521",
        }),
    }
}

/// Generate a key. A `Some("")` passphrase means unencrypted, like ssh-keygen.
pub fn generate(spec: &KeySpec, passphrase: Option<&str>) -> Result<PrivateKey, KeygenError> {
    let mut rng = OsRng;
    let bits = resolve_bits(spec.key_type, spec.bits)?;
    let key_data = match spec.key_type {
        KeyType::Ed25519 => KeypairData::from(Ed25519Keypair::random(&mut rng)),
        KeyType::Rsa => {
            let bits = bits.expect("resolve_bits gives rsa a size") as usize;
            KeypairData::from(RsaKeypair::random(&mut rng, bits)?)
        }
        KeyType::Ecdsa => {
            let curve = match bits.expect("resolve_bits gives ecdsa a size") {
                256 => EcdsaCurve::NistP256,
                384 => EcdsaCurve::NistP384,
                _ => EcdsaCurve::NistP521,
            };
            KeypairData::from(EcdsaKeypair::random(&mut rng, curve)?)
        }
    };
    let key = PrivateKey::new(key_data, spec.comment.clone())?;
    match passphrase {
        Some(p) if !p.is_empty() => {
            // `encrypt` rebuilds the public half from raw key data, which drops the
            // comment; put it back so the .pub file carries it.
            let mut encrypted = key.encrypt(&mut rng, p)?;
            encrypted.set_comment(spec.comment.clone());
            Ok(encrypted)
        }
        _ => Ok(key),
    }
}

/// Write `<name>` (0600) and `<name>.pub` (0644) into `ssh_dir` (0700).
/// Never leaves a half pair: if the .pub fails, the private key is removed again.
pub fn write_pair(
    ssh_dir: &Path,
    name: &str,
    key: &PrivateKey,
    force: bool,
) -> Result<Written, KeygenError> {
    fsx::ensure_private_dir(ssh_dir).map_err(|source| KeygenError::Io {
        path: ssh_dir.to_path_buf(),
        source,
    })?;
    let private_path = ssh_dir.join(name);
    let public_path = ssh_dir.join(format!("{name}.pub"));
    if !force {
        for p in [&private_path, &public_path] {
            if p.exists() {
                return Err(KeygenError::Exists(p.clone()));
            }
        }
    }
    let pem = key.to_openssh(LineEnding::LF)?; // Zeroizing<String>
    fsx::write_new(&private_path, pem.as_bytes(), 0o600, force).map_err(|source| {
        KeygenError::Io {
            path: private_path.clone(),
            source,
        }
    })?;
    let pub_line = format!("{}\n", key.public_key().to_openssh()?);
    if let Err(source) = fsx::write_new(&public_path, pub_line.as_bytes(), 0o644, force) {
        let _ = std::fs::remove_file(&private_path);
        return Err(KeygenError::Io {
            path: public_path,
            source,
        });
    }
    Ok(Written {
        private_path,
        public_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, EcdsaCurve, PublicKey};

    fn spec(key_type: KeyType, bits: Option<u32>) -> KeySpec {
        KeySpec {
            key_type,
            bits,
            comment: "t@h".into(),
        }
    }

    #[test]
    fn resolve_bits_table() {
        assert_eq!(resolve_bits(KeyType::Ed25519, None).unwrap(), None);
        assert!(matches!(
            resolve_bits(KeyType::Ed25519, Some(256)),
            Err(KeygenError::BitsNotApplicable)
        ));
        assert_eq!(resolve_bits(KeyType::Rsa, None).unwrap(), Some(4096));
        assert_eq!(resolve_bits(KeyType::Rsa, Some(3072)).unwrap(), Some(3072));
        assert!(matches!(
            resolve_bits(KeyType::Rsa, Some(1024)),
            Err(KeygenError::InvalidBits { bits: 1024, .. })
        ));
        assert_eq!(resolve_bits(KeyType::Ecdsa, None).unwrap(), Some(256));
        assert_eq!(resolve_bits(KeyType::Ecdsa, Some(521)).unwrap(), Some(521));
        assert!(matches!(
            resolve_bits(KeyType::Ecdsa, Some(512)),
            Err(KeygenError::InvalidBits { bits: 512, .. })
        ));
    }

    #[test]
    fn generates_ed25519_with_comment_unencrypted() {
        let key = generate(&spec(KeyType::Ed25519, None), None).unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(key.comment(), "t@h");
        assert!(!key.is_encrypted());
    }

    #[test]
    fn passphrase_encrypts_and_decrypts() {
        let key = generate(&spec(KeyType::Ed25519, None), Some("s3cret")).unwrap();
        assert!(key.is_encrypted());
        assert_eq!(
            key.comment(),
            "t@h",
            "comment must survive on the public half"
        );
        assert_eq!(key.public_key().to_openssh().unwrap().split(' ').count(), 3);
        let plain = key.decrypt("s3cret").unwrap();
        assert_eq!(plain.comment(), "t@h");
        assert!(key.decrypt("wrong").is_err());
    }

    #[test]
    fn empty_passphrase_means_unencrypted() {
        assert!(
            !generate(&spec(KeyType::Ed25519, None), Some(""))
                .unwrap()
                .is_encrypted()
        );
    }

    #[test]
    fn generates_ecdsa_384() {
        let key = generate(&spec(KeyType::Ecdsa, Some(384)), None).unwrap();
        assert_eq!(
            key.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384
            }
        );
    }

    #[test]
    fn generates_rsa_2048() {
        let key = generate(&spec(KeyType::Rsa, Some(2048)), None).unwrap();
        assert!(matches!(key.algorithm(), Algorithm::Rsa { .. }));
    }

    #[test]
    fn write_pair_creates_files_with_modes_and_refuses_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let ssh_dir = tmp.path().join("ssh");
        let key = generate(&spec(KeyType::Ed25519, None), None).unwrap();

        let w = write_pair(&ssh_dir, "work", &key, false).unwrap();
        assert_eq!(w.private_path, ssh_dir.join("work"));
        assert_eq!(w.public_path, ssh_dir.join("work.pub"));
        assert_eq!(crate::fsx::mode_of(&ssh_dir).unwrap(), 0o700);
        assert_eq!(crate::fsx::mode_of(&w.private_path).unwrap(), 0o600);
        assert_eq!(crate::fsx::mode_of(&w.public_path).unwrap(), 0o644);

        let pub_text = std::fs::read_to_string(&w.public_path).unwrap();
        assert!(pub_text.ends_with('\n'));
        let parsed = PublicKey::from_openssh(pub_text.trim()).unwrap();
        assert_eq!(parsed.comment(), "t@h");
        assert_eq!(
            parsed.fingerprint(ssh_key::HashAlg::Sha256),
            key.fingerprint(ssh_key::HashAlg::Sha256)
        );

        let reread = ssh_key::PrivateKey::read_openssh_file(&w.private_path).unwrap();
        assert_eq!(
            reread.fingerprint(ssh_key::HashAlg::Sha256),
            key.fingerprint(ssh_key::HashAlg::Sha256)
        );

        let other = generate(&spec(KeyType::Ed25519, None), None).unwrap();
        assert!(matches!(
            write_pair(&ssh_dir, "work", &other, false),
            Err(KeygenError::Exists(_))
        ));
        let forced = write_pair(&ssh_dir, "work", &other, true).unwrap();
        let reread = ssh_key::PrivateKey::read_openssh_file(&forced.private_path).unwrap();
        assert_eq!(
            reread.fingerprint(ssh_key::HashAlg::Sha256),
            other.fingerprint(ssh_key::HashAlg::Sha256)
        );
    }

    #[test]
    fn openssh_agrees_on_fingerprint_when_available() {
        let Ok(keygen) = which::which("ssh-keygen") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let key = generate(&spec(KeyType::Ed25519, None), None).unwrap();
        let w = write_pair(tmp.path(), "k", &key, false).unwrap();
        let out = std::process::Command::new(keygen)
            .args(["-l", "-f"])
            .arg(&w.public_path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(&key.fingerprint(ssh_key::HashAlg::Sha256).to_string()),
            "{text}"
        );
    }
}
