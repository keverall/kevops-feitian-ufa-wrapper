//! Argument parsing. Pure — no I/O, so it is covered by unit tests.

use crate::error::VaultError;
use crate::secret::SecretString;

/// A parsed vault command. No subcommand means [`Command::Derive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Derive and print the vault key (the default when no subcommand is given).
    Derive {
        /// Device PIN, when the authenticator demands `pinUvAuth`.
        /// Authenticators that accept biometric UV work without it.
        pin: Option<SecretString>,
    },
    /// List resident vault credentials without modifying the authenticator.
    List,
    /// Delete project-owned resident credentials after explicit confirmation.
    Delete,
    /// Register (and optionally replace) the vault credential.
    Enroll {
        /// Device PIN. When omitted, the CLI requests it through a hidden prompt.
        pin: Option<SecretString>,
    },
    /// Print usage.
    Help,
}

/// `--pin` option name.
const PIN_OPTION: &str = "--pin";

/// Usage banner, printed for `--help` and before any usage error.
pub const USAGE: &str = "\
usage: kevops-feitian-ufa-wrapper [command] [options]

commands:
  (none)        derive the vault key and print 64 hex chars to stdout
  enroll        register the vault credential (secure PIN prompt)
  list          list resident vault credentials (read-only)
  delete        delete project-owned credentials (confirmation required)

options:
  --pin <pin>   device PIN; omit to enter it securely at the prompt
  -h, --help    show this help
";

/// Parse the arguments that follow the program name.
///
/// # Errors
/// [`VaultError::UnknownCommand`] for an unknown subcommand or option,
/// [`VaultError::MissingPin`] for `--pin` without a value.
pub fn parse_args(args: &[String]) -> Result<Command, VaultError> {
    let Some(first) = args.first() else {
        return Ok(Command::Derive { pin: None });
    };

    match first.as_str() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "enroll" => Ok(Command::Enroll {
            pin: parse_pin_option(args.iter().skip(1))?,
        }),
        "list" => {
            if args.len() > 1 {
                return Err(VaultError::UnknownCommand(args[1].clone()));
            }
            Ok(Command::List)
        }
        "delete" => {
            if args.len() > 1 {
                return Err(VaultError::UnknownCommand(args[1].clone()));
            }
            Ok(Command::Delete)
        }
        // `derive` is the default command, so the subcommand word itself is optional.
        "derive" | "--pin" => {
            let skip = usize::from(first == "derive");
            Ok(Command::Derive {
                pin: parse_pin_option(args.iter().skip(skip))?,
            })
        }
        unknown => Err(VaultError::UnknownCommand(unknown.to_string())),
    }
}

/// The single option this CLI accepts, shared by every command (DRY).
fn parse_pin_option<'a>(
    mut options: impl Iterator<Item = &'a String>,
) -> Result<Option<SecretString>, VaultError> {
    let mut pin = None;

    while let Some(option) = options.next() {
        if let Some(value) = option.strip_prefix(&format!("{PIN_OPTION}=")) {
            pin = Some(SecretString::new(value.to_string()));
        } else if option == PIN_OPTION {
            match options.next() {
                Some(value) => pin = Some(SecretString::new(value.to_string())),
                None => return Err(VaultError::MissingPin),
            }
        } else {
            return Err(VaultError::UnknownCommand(option.clone()));
        }
    }

    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::VaultError;
    use crate::secret::SecretString;

    fn parse(values: &[&str]) -> Result<Command, VaultError> {
        let args: Vec<String> = values.iter().map(|value| value.to_string()).collect();
        parse_args(&args)
    }

    #[test]
    fn no_arguments_derives_the_key() {
        assert_eq!(parse(&[]).unwrap(), Command::Derive { pin: None });
    }

    #[test]
    fn derive_accepts_an_optional_pin() {
        for form in [vec!["derive", "--pin", "424242"], vec!["--pin", "424242"]] {
            assert_eq!(
                parse(&form).unwrap(),
                Command::Derive {
                    pin: Some(SecretString::new("424242".to_string()))
                }
            );
        }
    }

    #[test]
    fn list_is_a_read_only_command() {
        assert_eq!(parse(&["list"]).unwrap(), Command::List);
        assert_eq!(
            parse(&["list", "--pin"]).unwrap_err(),
            VaultError::UnknownCommand("--pin".to_string())
        );
    }

    #[test]
    fn help_is_a_command() {
        for flag in [["--help"], ["-h"], ["help"]] {
            assert_eq!(parse(&flag).unwrap(), Command::Help);
        }
    }

    #[test]
    fn enroll_without_a_pin_is_parsed_for_secure_prompting() {
        // Parsing succeeds so the binary can securely prompt for the PIN.
        assert_eq!(parse(&["enroll"]).unwrap(), Command::Enroll { pin: None });
    }

    #[test]
    fn enroll_accepts_a_space_separated_pin() {
        assert_eq!(
            parse(&["enroll", "--pin", "123456"]).unwrap(),
            Command::Enroll {
                pin: Some(SecretString::new("123456".to_string()))
            }
        );
    }

    #[test]
    fn enroll_accepts_an_equals_sign_separated_pin() {
        assert_eq!(
            parse(&["enroll", "--pin=123456"]).unwrap(),
            Command::Enroll {
                pin: Some(SecretString::new("123456".to_string()))
            }
        );
    }

    #[test]
    fn enroll_rejects_a_dangling_pin_option() {
        assert_eq!(
            parse(&["enroll", "--pin"]).unwrap_err(),
            VaultError::MissingPin
        );
    }

    #[test]
    fn unknown_subcommands_are_rejected() {
        assert_eq!(
            parse(&["bogus"]).unwrap_err(),
            VaultError::UnknownCommand("bogus".to_string())
        );
    }

    #[test]
    fn unknown_enroll_options_are_rejected() {
        assert_eq!(
            parse(&["enroll", "--verbose"]).unwrap_err(),
            VaultError::UnknownCommand("--verbose".to_string())
        );
    }

    #[test]
    fn usage_documents_both_commands_and_the_pin() {
        assert!(USAGE.contains("--pin <pin>"));
        assert!(USAGE.contains("enroll"));
        assert!(USAGE.contains("derive"));
    }
}
