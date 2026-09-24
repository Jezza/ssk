use std::process::ExitCode;

use clap::Parser;
use ssk::cli::{Cli, Command, ConfigAction};
use ssk::commands;
use ssk::settings::Settings;
use ssk::ui::Ui;

/// `ssk config path|set|unset|edit` must work on a config file ssk itself refuses to
/// load, or a typo in it could only be fixed by hand. `config get` still fails fast:
/// it is there to report the effective values, which a broken file does not have.
fn repairs_the_config(command: &Command) -> bool {
    matches!(command, Command::Config(args) if !matches!(args.action, ConfigAction::Get { .. }))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.json && !cli.command.supports_json() {
        eprintln!(
            "error: --json is not supported by `ssk {}` (list, show, doctor, hosts, config get)",
            cli.command.name()
        );
        return ExitCode::from(2);
    }
    let loaded = if repairs_the_config(&cli.command) {
        Settings::from_cli_lenient(&cli)
    } else {
        Settings::from_cli(&cli).map(|s| (s, None))
    };
    let (settings, problem) = match loaded {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("error: {err:#}");
            return ExitCode::from(1);
        }
    };
    let ui = Ui::new(&settings);
    if let Some(err) = problem {
        ui.warn(format!("{err:#}"));
    }
    let result = match &cli.command {
        Command::New(args) => commands::new::run(&settings, &ui, args),
        Command::Copy(args) => commands::copy::run(&settings, &ui, args),
        Command::List => commands::list::run(&settings, &ui),
        Command::Show(args) => commands::show::run(&settings, &ui, args),
        Command::Doctor(args) => commands::doctor::run(&settings, &ui, args),
        Command::Add(args) => commands::add::run(&settings, &ui, args),
        Command::Delete(args) => commands::rm::run(&settings, &ui, args),
        Command::Rename(args) => commands::rename::run(&settings, &ui, args),
        Command::Revoke(args) => commands::revoke::run(&settings, &ui, args),
        Command::Config(args) => commands::config::run(&settings, &ui, args),
        Command::Rotate(args) => commands::rotate::run(&settings, &ui, args),
        Command::Hosts => commands::hosts::run(&settings, &ui),
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
