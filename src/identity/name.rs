//! Identity name rules. The name is the filename, so the rules are filename rules
//! plus the handful of names ssh and ssk already use.

/// Filenames in the ssh dir that can never be identities.
pub const RESERVED: &[&str] = &[
    "config",
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "environment",
    "rc",
    "ssk.toml",
    "ssk.d",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("identity name is empty")]
    Empty,
    #[error("identity name may not start with '.'")]
    LeadingDot,
    #[error("identity name contains '{0}'; allowed: letters, digits, '.', '_', '-'")]
    BadChar(char),
    #[error("'{0}' is reserved by ssh or ssk and cannot be an identity name")]
    Reserved(String),
    #[error("identity name may not end in .pub")]
    PubSuffix,
}

/// `[A-Za-z0-9][A-Za-z0-9._-]*`, not reserved, not `*.pub`.
pub fn validate(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.starts_with('.') {
        return Err(NameError::LeadingDot);
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if let Some(bad) = name.chars().find(|c| !allowed(*c)) {
        return Err(NameError::BadChar(bad));
    }
    if RESERVED.contains(&name) {
        return Err(NameError::Reserved(name.to_string()));
    }
    if name.ends_with(".pub") {
        return Err(NameError::PubSuffix);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_conventional_names() {
        for n in [
            "work",
            "github",
            "id_ed25519",
            "aether_ed25519",
            "a.b-c_9",
            "X",
        ] {
            assert_eq!(validate(n), Ok(()), "{n}");
        }
    }

    #[test]
    fn rejects_empty_and_leading_dot() {
        assert_eq!(validate(""), Err(NameError::Empty));
        assert_eq!(validate(".hidden"), Err(NameError::LeadingDot));
    }

    #[test]
    fn rejects_bad_chars() {
        assert_eq!(validate("a/b"), Err(NameError::BadChar('/')));
        assert_eq!(validate("a b"), Err(NameError::BadChar(' ')));
        assert_eq!(validate("ü"), Err(NameError::BadChar('ü')));
    }

    #[test]
    fn rejects_every_reserved_name() {
        for n in RESERVED {
            assert_eq!(validate(n), Err(NameError::Reserved(n.to_string())), "{n}");
        }
    }

    #[test]
    fn rejects_pub_suffix() {
        assert_eq!(validate("work.pub"), Err(NameError::PubSuffix));
    }

    #[test]
    fn messages_are_helpful() {
        assert!(
            validate("config")
                .unwrap_err()
                .to_string()
                .contains("reserved")
        );
        assert!(validate("a/b").unwrap_err().to_string().contains("'/'"));
    }
}
