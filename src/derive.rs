//! Key derivation flow: ask the device for the hmac-secret, hash it to a key.

use crate::crypto::{self, VAULT_KEY_SIZE};
use crate::device::VaultDevice;
use crate::error::VaultError;

/// User-facing prompt shown while waiting for the finger on the sensor.
pub const TOUCH_PROMPT: &str = "⚡ Please tap the Feitian BioPass fingerprint sensor...";

/// User-facing confirmation, printed to stderr once the key is derived.
pub const KEY_DERIVED_MESSAGE: &str = "🔓 Fingerprint verified! 256-bit Vault key derived.";

/// User-facing confirmation for PIN-authorised derivation.
///
/// A PIN-authorised assertion sets `uv = None`, so the fingerprint is **not**
/// re-checked and this must not claim otherwise.
pub const KEY_DERIVED_WITH_PIN_MESSAGE: &str =
    "🔐 PIN verified! 256-bit Vault key derived (fingerprint was NOT re-checked).";

/// The confirmation for a derivation, chosen by how it was authorised.
pub fn key_derived_message(pin: Option<&str>) -> &'static str {
    match pin {
        Some(_) => KEY_DERIVED_WITH_PIN_MESSAGE,
        None => KEY_DERIVED_MESSAGE,
    }
}

/// Derive the 32-byte AES-256 vault key from the authenticator.
///
/// Presentational output is the caller's job, so this stays testable: it only
/// performs the device request and the key derivation.
///
/// # Errors
/// [`VaultError::Device`] when the transport or a CTAP call fails, including the
/// `CTAP2_ERR_PIN_REQUIRED` the BioPass answers for hmac-secret without a PIN.
pub fn derive_vault_key(
    device: &dyn VaultDevice,
    salt_label: &str,
    pin: Option<&str>,
) -> Result<[u8; VAULT_KEY_SIZE], VaultError> {
    let hmac_secret = device
        .hmac_secret(salt_label, pin)
        .map_err(VaultError::device)?;
    Ok(crypto::derive_vault_key(&hmac_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceResult, StoredCredential};

    struct Fake {
        secret: Option<[u8; 32]>,
        error: Option<&'static str>,
    }

    impl VaultDevice for Fake {
        fn list_credentials(&self, _pin: &str) -> DeviceResult<Vec<StoredCredential>> {
            unimplemented!("derive does not enrol")
        }
        fn create_credential(&self, _pin: &str) -> DeviceResult<Vec<u8>> {
            unimplemented!("derive does not enrol")
        }
        fn rename_credential(&self, _pin: &str, _id: &[u8], _name: &str) -> DeviceResult<()> {
            unimplemented!("derive does not enrol")
        }
        fn delete_credential(&self, _pin: &str, _id: &[u8]) -> DeviceResult<()> {
            unimplemented!("derive does not enrol")
        }
        fn hmac_secret(&self, _salt_label: &str, _pin: Option<&str>) -> DeviceResult<[u8; 32]> {
            match (self.secret, self.error) {
                (_, Some(message)) => Err(message.into()),
                (Some(secret), _) => Ok(secret),
                (None, None) => Err("no secret configured".into()),
            }
        }
    }

    #[test]
    fn derives_the_key_the_same_way_the_crypto_layer_does() {
        let secret = [0x5au8; 32];
        let key = derive_vault_key(
            &Fake {
                secret: Some(secret),
                error: None,
            },
            "salt",
            None,
        )
        .expect("a secret yields a key");
        assert_eq!(key, crypto::derive_vault_key(&secret));
        assert_eq!(key.len(), VAULT_KEY_SIZE);
    }

    #[test]
    fn the_salt_label_is_forwarded_unchanged() {
        let secret = [0x11u8; 32];
        let key = derive_vault_key(
            &Fake {
                secret: Some(secret),
                error: None,
            },
            "label",
            Some("123456"),
        )
        .expect("a secret yields a key");
        assert_eq!(key, crypto::derive_vault_key(&secret));
    }

    #[test]
    fn the_pin_derivation_message_never_claims_a_fingerprint_was_used() {
        let message = key_derived_message(Some("123456"));
        assert!(!message.contains("Fingerprint"));
        assert!(message.contains("PIN"));
        assert!(message.contains("NOT re-checked"));
    }

    #[test]
    fn uv_derivation_reports_the_fingerprint() {
        assert_eq!(key_derived_message(None), KEY_DERIVED_MESSAGE);
    }

    #[test]
    fn transport_failures_are_reported_as_device_errors() {
        let error = derive_vault_key(
            &Fake {
                secret: None,
                error: Some("device gone"),
            },
            "salt",
            None,
        )
        .expect_err("a transport failure is an error");
        assert_eq!(error, VaultError::device("device gone"));
    }
}
