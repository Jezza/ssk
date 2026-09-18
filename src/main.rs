use std::process::ExitCode;

use clap::Parser;
use ssk::cli::{Cli, Command};
use ssk::commands;
use ssk::settings::Settings;
use ssk::ui::Ui;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let settings = match Settings::from_cli(&cli) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error: {err:#}");
            return ExitCode::from(1);
        }
    };
    let ui = Ui::new(&settings);
    let result = match &cli.command {
        Command::New(args) => commands::new::run(&settings, &ui, args),
        Command::Copy(args) => commands::copy::run(&settings, &ui, args),
        Command::List => commands::list::run(&settings, &ui),
        Command::Show(args) => commands::show::run(&settings, &ui, args),
        Command::Doctor(args) => commands::doctor::run(&settings, &ui, args),
        Command::Completions { shell } => commands::completions::run(*shell),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            ui.error(format!("{err:#}"));
            ExitCode::from(1)
        }
    }
}
