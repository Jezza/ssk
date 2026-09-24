use std::process::ExitCode;

use ssk::args::{self, Command};
use ssk::cmd;
use ssk::settings::Settings;
use ssk::ui::Ui;

/// `ssk config path|set|unset|edit` must work on a config file ssk itself refuses to
/// load, or a typo in it could only be fixed by hand. `config get` still fails fast:
/// it is there to report the effective values, which a broken file does not have.
fn repairs_the_config(command: &Command) -> bool {
    matches!(command, Command::Config(config) if !matches!(config.cmd, cmd::config::Cmd::Get(_)))
}

fn main() -> ExitCode {
    let args::Args { ctx, command } = clap::Parser::parse();
    if ctx.json && !command.supports_json() {
        eprintln!(
            "error: --json is not supported by `ssk {}` (list, show, doctor, hosts, config get)",
            command.name()
        );
        return ExitCode::from(2);
    }
    let loaded = if repairs_the_config(&command) {
        Settings::from_ctx_lenient(&ctx)
    } else {
        Settings::from_ctx(&ctx).map(|s| (s, None))
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
    let result = match &command {
        Command::New(args) => cmd::new::handle(&settings, &ui, args),
        Command::Copy(args) => cmd::copy::handle(&settings, &ui, args),
        Command::List(args) => cmd::list::handle(&settings, &ui, args),
        Command::Show(args) => cmd::show::handle(&settings, &ui, args),
        Command::Doctor(args) => cmd::doctor::handle(&settings, &ui, args),
        Command::Add(args) => cmd::add::handle(&settings, &ui, args),
        Command::Delete(args) => cmd::delete::handle(&settings, &ui, args),
        Command::Rename(args) => cmd::rename::handle(&settings, &ui, args),
        Command::Revoke(args) => cmd::revoke::handle(&settings, &ui, args),
        Command::Config(args) => cmd::config::handle(&settings, &ui, args),
        Command::Rotate(args) => cmd::rotate::handle(&settings, &ui, args),
        Command::Hosts(args) => cmd::hosts::handle(&settings, &ui, args),
        Command::Completions(args) => cmd::completions::handle(args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            ui.error(format!("{err:#}"));
            ExitCode::from(1)
        }
    }
}
