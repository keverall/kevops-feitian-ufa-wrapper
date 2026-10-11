//! Secret string handling for PIN values.

use std::fmt;
use zeroize::Zeroize;

/// An owned PIN that is redacted in diagnostics and zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Stores a PIN without exposing it through formatting or debugging.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Exposes the PIN only for the short duration required by the device API.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(REDACTED)")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_the_pin() {
        let pin = SecretString::new("123456".to_string());
        let debug = format!("{pin:?}");
        assert_eq!(debug, "SecretString(REDACTED)");
        assert!(!debug.contains("123456"));
    }
}
