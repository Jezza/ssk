//! Everything that spawns `ssh` or `ssh-add`.

pub mod agent;
pub mod config;
pub mod install;
pub mod probe;
pub mod revoke;
pub mod runner;

use crate::target::Target;

/// `-p`/`-l` from the target, then `-o K=V` for each extra option. The host is
/// never here: callers append `--` and the host themselves.
pub fn target_args(target: &Target, extra_options: &[String]) -> Vec<String> {
    let mut args = target.ssh_args();
    for opt in extra_options {
        args.push("-o".to_string());
        args.push(opt.clone());
    }
    args
}

/// `-o IdentitiesOnly=yes` for the install and revoke steps. Without it ssh offers every
/// agent key before anything else, and each rejected key counts against sshd's
/// `MaxAuthTries` (6 by default): an agent holding six keys ends in "Too many
/// authentication failures" before a password is ever asked for. With it ssh still tries
/// any `-i`, the `IdentityFile` lines the ssh config matches for the host and the default
/// `~/.ssh/id_*` files (through the agent when they are loaded there), then passwords.
/// Callers append this *after* `target_args` so a `--ssh-option IdentitiesOnly=no` wins:
/// ssh keeps the first value it sees for an option.
pub fn identities_only() -> [String; 2] {
    ["-o".to_string(), "IdentitiesOnly=yes".to_string()]
}
