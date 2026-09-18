//! Terminal output and prompts. Every command talks to the user through `Ui`
//! so `--quiet`, `--yes` and colour are handled in one place.

use std::io::{self, IsTerminal};

use anyhow::bail;
use owo_colors::{OwoColorize, Stream};

use crate::cli::ColorChoice;
use crate::settings::Settings;

pub struct Ui {
    /// --quiet, or --json (human stdout would corrupt the document).
    quiet: bool,
    verbose: u8,
    yes: bool,
}

impl Ui {
    pub fn new(settings: &Settings) -> Ui {
        match settings.color {
            ColorChoice::Always => owo_colors::set_override(true),
            ColorChoice::Never => owo_colors::set_override(false),
            ColorChoice::Auto => owo_colors::unset_override(),
        }
        Ui {
            quiet: settings.quiet || settings.json,
            verbose: settings.verbose,
            yes: settings.yes,
        }
    }

    /// For tests: prints nothing, answers yes, no colour.
    pub fn silent() -> Ui {
        owo_colors::set_override(false);
        Ui {
            quiet: true,
            verbose: 0,
            yes: true,
        }
    }

    pub fn verbose(&self) -> u8 {
        self.verbose
    }

    pub fn info(&self, msg: impl AsRef<str>) {
        if !self.quiet {
            println!("{}", msg.as_ref());
        }
    }

    pub fn success(&self, msg: impl AsRef<str>) {
        if !self.quiet {
            println!(
                "{} {}",
                "ok".if_supports_color(Stream::Stdout, |t| t.green()),
                msg.as_ref()
            );
        }
    }

    pub fn hint(&self, msg: impl AsRef<str>) {
        if !self.quiet {
            println!(
                "{} {}",
                "next:".if_supports_color(Stream::Stdout, |t| t.dimmed()),
                msg.as_ref()
            );
        }
    }

    pub fn warn(&self, msg: impl AsRef<str>) {
        eprintln!(
            "{} {}",
            "warning:".if_supports_color(Stream::Stderr, |t| t.yellow()),
            msg.as_ref()
        );
    }

    pub fn error(&self, msg: impl AsRef<str>) {
        eprintln!(
            "{} {}",
            "error:".if_supports_color(Stream::Stderr, |t| t.red()),
            msg.as_ref()
        );
    }

    /// Echo an external command when `-v` is on.
    pub fn command(&self, program: &str, args: &[String]) {
        if self.verbose > 0 {
            eprintln!("$ {} {}", program, shell_join(args));
        }
    }

    /// Yes/no prompt. `--yes` short-circuits to true; no terminal is an error, never a guess.
    pub fn confirm(&self, prompt: &str) -> anyhow::Result<bool> {
        if self.yes {
            return Ok(true);
        }
        if !io::stdin().is_terminal() {
            bail!("{prompt}: no terminal to ask on; pass --yes to proceed");
        }
        Ok(dialoguer::Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()?)
    }

    /// Hidden-input prompt; `confirmation` = (repeat prompt, mismatch message).
    pub fn password(
        &self,
        prompt: &str,
        confirmation: Option<(&str, &str)>,
    ) -> anyhow::Result<String> {
        let mut p = dialoguer::Password::new()
            .with_prompt(prompt)
            .allow_empty_password(true);
        if let Some((again, mismatch)) = confirmation {
            p = p.with_confirmation(again, mismatch);
        }
        Ok(p.interact()?)
    }
}

/// Join argv for display, quoting anything a shell would mangle.
pub fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn shell_quote(arg: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c);
    if !arg.is_empty() && arg.chars().all(safe) {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_leaves_safe_words_alone() {
        assert_eq!(shell_quote("-o"), "-o");
        assert_eq!(shell_quote("ControlPath=none"), "ControlPath=none");
        assert_eq!(shell_quote("/home/x/.ssh/work"), "/home/x/.ssh/work");
    }

    #[test]
    fn shell_quote_wraps_and_escapes() {
        assert_eq!(shell_quote("exec sh -c 'x'"), "'exec sh -c '\\''x'\\'''");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shell_join_spaces_args() {
        let args = vec!["-p".to_string(), "22".to_string(), "a b".to_string()];
        assert_eq!(shell_join(&args), "-p 22 'a b'");
    }
}
