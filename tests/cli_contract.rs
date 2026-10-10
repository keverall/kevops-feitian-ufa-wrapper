//! Contract tests for the CLI's argument parsing and error surface.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use kevops_feitian_ufa_wrapper::cli::{self, Command};
use kevops_feitian_ufa_wrapper::error::VaultError;

fn parse(values: &[&str]) -> Result<Command, VaultError> {
    let args: Vec<String> = values.iter().map(|value| value.to_string()).collect();
    cli::parse_args(&args)
}

#[test]
fn no_arguments_means_derive() {
    assert_eq!(parse(&[]).unwrap(), Command::Derive { pin: None });
}

#[test]
fn help_short_circuits_before_any_device_access() {
    assert_eq!(parse(&["--help"]).unwrap(), Command::Help);
}

#[test]
fn the_pin_is_carried_into_enrolment() {
    assert_eq!(
        parse(&["enroll", "--pin", "424242"]).unwrap(),
        Command::Enroll {
            pin: Some("424242".to_string())
        }
    );
}

#[test]
fn enrolment_without_a_pin_is_reported_as_a_usage_error() {
    assert_eq!(parse(&["enroll"]).unwrap(), Command::Enroll { pin: None });
    assert_eq!(VaultError::MissingPin.exit_code(), 2);
    assert!(VaultError::MissingPin.to_string().contains("--pin"));
}

#[test]
fn unknown_commands_are_rejected_with_exit_code_two() {
    let error = parse(&["unlock"]).unwrap_err();
    assert_eq!(error, VaultError::UnknownCommand("unlock".to_string()));
    assert_eq!(error.exit_code(), 2);
}
