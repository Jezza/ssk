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
