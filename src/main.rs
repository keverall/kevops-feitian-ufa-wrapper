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
use kevops_feitian_ufa_wrapper::secret::SecretString;

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
        Command::Derive { pin } => with_device(|device| {
            print_vault_key(device, pin.as_ref().map(SecretString::expose_secret))
        }),
        Command::List => {
            let pin = prompt_for_pin()?;
            with_device(|device| list_credentials(device, pin))
        }
        Command::Delete => {
            let pin = prompt_for_pin()?;
            with_device(|device| delete_credentials(device, pin))
        }
        Command::Enroll { pin } => {
            let pin = pin.map_or_else(prompt_for_pin, Ok)?;
            with_device(|device| enroll_credential(device, pin))
        }
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

fn list_credentials(device: &dyn VaultDevice, pin: SecretString) -> Result<(), Failure> {
    let credentials = device
        .list_credentials(pin.expose_secret())
        .map_err(Failure::runtime)?;

    if credentials.is_empty() {
        println!("No resident credentials found for RP '{RP_ID}'.");
        return Ok(());
    }

    println!(
        "{} resident credential(s) for RP '{RP_ID}':",
        credentials.len()
    );
    for (index, credential) in credentials.iter().enumerate() {
        println!(
            "{}. name={:?} display_name={:?} id={}",
            index + 1,
            credential.name,
            credential.display_name,
            crypto::to_hex(&credential.credential_id)
        );
    }
    Ok(())
}

fn delete_credentials(device: &dyn VaultDevice, pin: SecretString) -> Result<(), Failure> {
    let deleted = enroll::delete_vault_credentials(device, pin.expose_secret(), |credentials| {
        if credentials.is_empty() {
            eprintln!("No project-owned credentials found; nothing will be deleted.");
            return false;
        }
        eprintln!("The following project-owned credential(s) will be deleted:");
        for credential in credentials {
            eprintln!("- {:?} ({:?})", credential.name, credential.display_name);
        }
        eprint!("Type YES to permanently delete them: ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).is_ok() && answer.trim() == "YES"
    })
    .map_err(Failure::runtime)?;

    if deleted.is_empty() {
        eprintln!("No credentials deleted.");
    } else {
        eprintln!("Deleted {} project-owned credential(s).", deleted.len());
    }
    Ok(())
}

fn enroll_credential(device: &dyn VaultDevice, pin: SecretString) -> Result<(), Failure> {
    let name = enroll::enroll_vault_credential(device, pin.expose_secret(), replace_policy())
        .map_err(Failure::runtime)?;
    eprintln!("✅ Enrolled vault credential '{name}' for RP '{RP_ID}'.");
    Ok(())
}

fn prompt_for_pin() -> Result<SecretString, Failure> {
    rpassword::prompt_password("Device PIN: ")
        .map(SecretString::new)
        .map_err(Failure::runtime)
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
