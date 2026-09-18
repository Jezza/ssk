//! Key generation. Task 6 fills in `KeySpec`, `generate` and `write_pair`.

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
