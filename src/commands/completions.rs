use std::io;

use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::Cli;

pub fn run(shell: Shell) -> anyhow::Result<u8> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "ssk", &mut io::stdout());
    Ok(0)
}
