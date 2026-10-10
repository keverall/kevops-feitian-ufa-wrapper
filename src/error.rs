//! The single error type of the vault CLI, with user-facing messages.

use std::fmt;

/// Every way the vault flows can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// A command that needs a PIN was used without `--pin`.
    MissingPin,
    /// A subcommand or option that this CLI does not recognise.
    UnknownCommand(String),
    /// The authenticator returned no assertion for the vault RP id.
    NoAssertion,
    /// The assertion carried no hmac-secret output.
    MissingHmacSecret,
    /// A transport or CTAP failure reported by the authenticator.
    Device(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPin => write!(f, "missing PIN: pass `--pin <pin>`"),
            Self::UnknownCommand(command) => {
                write!(f, "unknown command: {command:?} (expected `enroll`)")
            }
            Self::NoAssertion => write!(f, "no assertion returned by the authenticator"),
            Self::MissingHmacSecret => {
                write!(f, "the authenticator returned no hmac-secret output")
            }
            Self::Device(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl VaultError {
    /// Wrap an error surfaced by the [`crate::device`] boundary.
    pub fn device<E: fmt::Display>(error: E) -> Self {
        Self::Device(error.to_string())
    }

    /// Process exit code: usage errors and runtime failures differ by one digit.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::MissingPin | Self::UnknownCommand(_) => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_missing_pin_message_names_the_option() {
        let message = VaultError::MissingPin.to_string();
        assert!(message.contains("--pin <pin>"));
        // Command-agnostic: the same text serves `enroll` and `derive`.
        assert!(!message.contains("enroll requires"));
    }

    #[test]
    fn exit_codes_separate_usage_from_runtime_failures() {
        assert_eq!(VaultError::MissingPin.exit_code(), 2);
        assert_eq!(VaultError::UnknownCommand("x".into()).exit_code(), 2);
        assert_eq!(VaultError::NoAssertion.exit_code(), 1);
        assert_eq!(VaultError::Device("boom".into()).exit_code(), 1);
    }

    #[test]
    fn device_errors_carry_the_underlying_message() {
        assert_eq!(VaultError::device("no device").to_string(), "no device");
    }

    #[test]
    fn implements_std_error() {
        let error: &dyn std::error::Error = &VaultError::MissingHmacSecret;
        assert!(error.source().is_none());
    }
}
