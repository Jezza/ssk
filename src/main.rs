use std::process::ExitCode;

use clap::Parser;
use ssk::cli::{Cli, Command};
use ssk::commands;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Completions { shell } => commands::completions::run(*shell),
        other => Err(anyhow::anyhow!(
            "`ssk {}` is not implemented yet",
            other.name()
        )),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}
