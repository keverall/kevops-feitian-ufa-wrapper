//! Thin CLI front-end: parse arguments, wire the real device, render results.
//!
//! All logic lives in the library crate; this file is argument handling and
//! presentation only, so it stays small.

use std::io::Write;
use std::process::ExitCode;

use kevops_feitian_ufa_wrapper::cli::{self, Command};
use kevops_feitian_ufa_wrapper::config::{RP_ID, SALT_LABEL};
use kevops_feitian_ufa_wrapper::crypto;
use kevops_feitian_ufa_wrapper::derive::{self, TOUCH_PROMPT, key_derived_message};
use kevops_feitian_ufa_wrapper::device::{
    FidoKeyHidDevice, StoredCredential, VaultDevice, open_device,
};
use kevops_feitian_ufa_wrapper::enroll::{self, ReplacePolicy};
use kevops_feitian_ufa_wrapper::error::VaultError;

/// Exit code for runtime and device failures.
const EXIT_RUNTIME: u8 = 1;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("Error: {failure}");
            ExitCode::from(failure.exit_code())
        }
    }
}

/// Parse, then delegate to the flow that owns the device.
fn run(args: &[String]) -> Result<(), Failure> {
    match cli::parse_args(args).map_err(Failure::usage)? {
        Command::Help => {
            print!("{}", cli::USAGE);
            Ok(())
        }
        Command::Derive { pin } => with_device(|device| print_vault_key(device, pin.as_deref())),
        Command::Enroll { pin: None } => Err(Failure::usage(VaultError::MissingPin)),
        Command::Enroll { pin: Some(pin) } => with_device(|device| enroll_credential(device, pin)),
    }
}

/// Open the real device for the duration of `action`.
fn with_device(
    action: impl FnOnce(&dyn VaultDevice) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let device = open_device().map_err(Failure::runtime)?;
    let vault_device = FidoKeyHidDevice::new(&device);
    action(&vault_device)
}

/// stdout carries the 64-char key only; every human message goes to stderr.
fn print_vault_key(device: &dyn VaultDevice, pin: Option<&str>) -> Result<(), Failure> {
    eprintln!("{}", TOUCH_PROMPT);
    let key = derive::derive_vault_key(device, SALT_LABEL, pin).map_err(Failure::runtime)?;
    eprintln!("{}", key_derived_message(pin));
    print!("{}", crypto::encode_key(&key));
    std::io::stdout().flush().map_err(Failure::runtime)?;
    Ok(())
}

fn enroll_credential(device: &dyn VaultDevice, pin: String) -> Result<(), Failure> {
    let name = enroll::enroll_vault_credential(device, &pin, replace_policy())
        .map_err(Failure::runtime)?;
    eprintln!("✅ Enrolled vault credential '{name}' for RP '{RP_ID}'.");
    Ok(())
}

/// `R` replaces the existing credentials; anything else (including Enter) adds.
fn replace_policy() -> ReplacePolicy {
    ReplacePolicy::Ask(Box::new(|existing: &[StoredCredential]| {
        eprintln!(
            "ℹ️ Found {} existing vault credential(s) for RP '{RP_ID}'.",
            existing.len()
        );
        eprint!("   Replace existing (R) or add a new one (A)? [R/A]: ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() {
            return false;
        }
        answer.trim().eq_ignore_ascii_case("R")
    }))
}

/// A failure paired with the exit code its presentation deserves.
#[derive(Debug)]
enum Failure {
    /// Bad input: report on stderr, exit code 2.
    Usage(VaultError),
    /// Everything else: report on stderr, exit code 1.
    Runtime(VaultError),
}

impl Failure {
    fn usage(error: VaultError) -> Self {
        Self::Usage(error)
    }

    fn runtime<E: std::fmt::Display>(error: E) -> Self {
        Self::Runtime(VaultError::device(error))
    }

    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(error) => error.exit_code(),
            Self::Runtime(_) => EXIT_RUNTIME,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) | Self::Runtime(error) => write!(f, "{error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_enrollment_pin_is_rejected_before_opening_hardware() {
        let args = vec!["enroll".to_string()];
        let error = run(&args).expect_err("missing PIN must be a usage error");
        assert!(matches!(error, Failure::Usage(VaultError::MissingPin)));
    }
}
