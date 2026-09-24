use std::io;

use clap::CommandFactory;
use clap_complete::Shell;

use crate::args::Args;

#[derive(clap::Parser, Debug)]
pub struct Completions {
    #[arg(value_enum)]
    pub shell: Shell,
}

pub fn handle(args: &Completions) -> anyhow::Result<u8> {
    let mut cmd = Args::command();
    clap_complete::generate(args.shell, &mut cmd, "ssk", &mut io::stdout());
    Ok(0)
}
