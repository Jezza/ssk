//! An identity is a name that resolves to `<ssh_dir>/<name>` and `<name>.pub`.
//! Everything about it is read from those files on demand.

pub mod comment;
pub mod keygen;
pub mod name;
pub mod store;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub private_path: PathBuf,
    /// `None` when `<name>.pub` is missing.
    pub public_path: Option<PathBuf>,
    /// `ed25519`, `rsa`, `ecdsa`, `dsa`, or the raw algorithm name.
    pub algorithm: String,
    /// RSA modulus bits or ECDSA curve size.
    pub bits: Option<u32>,
    /// `SHA256:...`
    pub fingerprint: String,
    pub encrypted: bool,
    pub comment: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("cannot read {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is not an OpenSSH private key: {source}", .path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: ssh_key::Error,
    },
    #[error("{p} is a legacy PEM private key; convert it with `ssh-keygen -p -f {p}`", p = .path.display())]
    LegacyPem { path: PathBuf },
    #[error("identity '{name}' has no .pub file; run `ssk doctor --fix` to regenerate it")]
    NoPublicKey { name: String },
}

impl Identity {
    pub fn load(ssh_dir: &Path, name: &str) -> Result<Identity, IdentityError> {
        let private_path = ssh_dir.join(name);
        let pem = Zeroizing::new(fs::read_to_string(&private_path).map_err(|source| {
            IdentityError::Read {
                path: private_path.clone(),
                source,
            }
        })?);
        if is_legacy_pem(&pem) {
            return Err(IdentityError::LegacyPem { path: private_path });
        }
        let key =
            PrivateKey::from_openssh(pem.as_bytes()).map_err(|source| IdentityError::Parse {
                path: private_path.clone(),
                source,
            })?;

        let public_path = ssh_dir.join(format!("{name}.pub"));
        let public_path = public_path.is_file().then_some(public_path);
        // The comment inside an encrypted private key is itself encrypted; the .pub has it in clear.
        let pub_comment = public_path
            .as_ref()
            .and_then(|p| PublicKey::read_openssh_file(p).ok())
            .map(|k| k.comment().to_string())
            .filter(|c| !c.is_empty());

        let (algorithm, bits) = describe(key.public_key());
        Ok(Identity {
            name: name.to_string(),
            private_path,
            public_path,
            algorithm,
            bits,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            encrypted: key.is_encrypted(),
            comment: pub_comment.unwrap_or_else(|| key.comment().to_string()),
        })
    }

    /// The one-line authorized_keys form from the .pub file, trimmed.
    pub fn public_key_line(&self) -> Result<String, IdentityError> {
        let path = self
            .public_path
            .as_ref()
            .ok_or_else(|| IdentityError::NoPublicKey {
                name: self.name.clone(),
            })?;
        let text = fs::read_to_string(path).map_err(|source| IdentityError::Read {
            path: path.clone(),
            source,
        })?;
        Ok(text.trim().to_string())
    }

    pub fn type_label(&self) -> String {
        match self.bits {
            Some(b) => format!("{} {b}", self.algorithm),
            None => self.algorithm.clone(),
        }
    }
}

/// PEM that isn't the OpenSSH container: `-----BEGIN RSA PRIVATE KEY-----` and friends.
pub fn is_legacy_pem(text: &str) -> bool {
    text.starts_with("-----BEGIN ") && !text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
}

/// Human algorithm name plus size where it means something.
pub fn describe(key: &PublicKey) -> (String, Option<u32>) {
    match key.algorithm() {
        Algorithm::Ed25519 => ("ed25519".to_string(), None),
        Algorithm::Rsa { .. } => {
            let bits = match key.key_data() {
                KeyData::Rsa(rsa) => rsa
                    .n
                    .as_positive_bytes()
                    .filter(|b| !b.is_empty())
                    .map(|b| (b.len() * 8 - b[0].leading_zeros() as usize) as u32),
                _ => None,
            };
            ("rsa".to_string(), bits)
        }
        Algorithm::Ecdsa { curve } => {
            let bits = match curve {
                EcdsaCurve::NistP256 => 256,
                EcdsaCurve::NistP384 => 384,
                EcdsaCurve::NistP521 => 521,
            };
            ("ecdsa".to_string(), Some(bits))
        }
        Algorithm::Dsa => ("dsa".to_string(), None),
        other => (other.as_str().to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keygen::{KeySpec, KeyType, generate, write_pair};

    fn make(
        ssh_dir: &Path,
        name: &str,
        key_type: KeyType,
        pass: Option<&str>,
    ) -> ssh_key::PrivateKey {
        let key = generate(
            &KeySpec {
                key_type,
                bits: None,
                comment: format!("{name}@box"),
            },
            pass,
        )
        .unwrap();
        write_pair(ssh_dir, name, &key, false).unwrap();
        key
    }

    #[test]
    fn loads_unencrypted_ed25519() {
        let tmp = tempfile::tempdir().unwrap();
        let key = make(tmp.path(), "work", KeyType::Ed25519, None);
        let id = Identity::load(tmp.path(), "work").unwrap();
        assert_eq!(id.name, "work");
        assert_eq!(id.algorithm, "ed25519");
        assert_eq!(id.bits, None);
        assert_eq!(id.type_label(), "ed25519");
        assert_eq!(
            id.fingerprint,
            key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
        );
        assert!(!id.encrypted);
        assert_eq!(id.comment, "work@box");
        assert_eq!(id.public_path, Some(tmp.path().join("work.pub")));
        assert!(id.public_key_line().unwrap().starts_with("ssh-ed25519 "));
    }

    #[test]
    fn encrypted_key_reports_encrypted_and_reads_comment_from_pub() {
        let tmp = tempfile::tempdir().unwrap();
        make(tmp.path(), "vault", KeyType::Ed25519, Some("pw"));
        let id = Identity::load(tmp.path(), "vault").unwrap();
        assert!(id.encrypted);
        assert_eq!(id.comment, "vault@box");
    }

    #[test]
    fn ecdsa_reports_curve_bits() {
        let tmp = tempfile::tempdir().unwrap();
        make(tmp.path(), "e", KeyType::Ecdsa, None);
        let id = Identity::load(tmp.path(), "e").unwrap();
        assert_eq!((id.algorithm.as_str(), id.bits), ("ecdsa", Some(256)));
        assert_eq!(id.type_label(), "ecdsa 256");
    }

    #[test]
    fn missing_pub_is_none_and_public_key_line_errors() {
        let tmp = tempfile::tempdir().unwrap();
        make(tmp.path(), "lonely", KeyType::Ed25519, None);
        std::fs::remove_file(tmp.path().join("lonely.pub")).unwrap();
        let id = Identity::load(tmp.path(), "lonely").unwrap();
        assert_eq!(id.public_path, None);
        assert!(matches!(
            id.public_key_line(),
            Err(IdentityError::NoPublicKey { .. })
        ));
    }

    #[test]
    fn legacy_pem_is_reported_as_such() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("old"),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(matches!(
            Identity::load(tmp.path(), "old"),
            Err(IdentityError::LegacyPem { .. })
        ));
        assert!(is_legacy_pem("-----BEGIN EC PRIVATE KEY-----"));
        assert!(!is_legacy_pem("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn garbage_is_a_parse_error() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("junk"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(matches!(
            Identity::load(tmp.path(), "junk"),
            Err(IdentityError::Parse { .. })
        ));
    }
}
