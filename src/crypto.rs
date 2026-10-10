//! Key derivation and hex encoding. Pure functions — no I/O, no device.

use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Size of the derived AES-256 key, in bytes.
pub const VAULT_KEY_SIZE: usize = 32;

/// Length of the lowercase hex encoding of a full vault key.
pub const HEX_KEY_LENGTH: usize = VAULT_KEY_SIZE * 2;

/// Derive the AES-256 vault key from the on-device hmac-secret output.
///
/// The hmac-secret output is hashed once more so the key is a fixed 32 bytes
/// regardless of the authenticator's output length.
///
/// ```
/// use kevops_feitian_ufa_wrapper::crypto;
///
/// let key = crypto::derive_vault_key(&[0x42; 32]);
/// assert_eq!(key.len(), crypto::VAULT_KEY_SIZE);
/// assert_eq!(crypto::encode_key(&key).len(), crypto::HEX_KEY_LENGTH);
/// ```
pub fn derive_vault_key(hmac_secret: &[u8]) -> [u8; VAULT_KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(hmac_secret);
    let mut key = [0u8; VAULT_KEY_SIZE];
    key.copy_from_slice(&hasher.finalize());
    key
}

/// Lowercase hex encoding of arbitrary bytes, without separators.
///
/// ```
/// use kevops_feitian_ufa_wrapper::crypto;
///
/// assert_eq!(crypto::to_hex(&[0x00, 0x0a, 0xff]), "000aff");
/// ```
pub fn to_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // `write!` to a `String` is infallible.
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Lowercase hex encoding of a vault key: always 64 characters.
pub fn encode_key(key: &[u8; VAULT_KEY_SIZE]) -> String {
    to_hex(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding_is_lowercase_and_fixed_width() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(encode_key(&[0u8; 32]).len(), HEX_KEY_LENGTH);
    }

    #[test]
    fn derivation_is_deterministic_and_32_bytes() {
        let expected = derive_vault_key(&[0x42; 32]);
        assert_eq!(expected.len(), VAULT_KEY_SIZE);
        assert_eq!(expected, derive_vault_key(&[0x42; 32]));
    }

    #[test]
    fn different_secrets_yield_different_keys() {
        assert_ne!(derive_vault_key(&[0x00; 32]), derive_vault_key(&[0x01; 32]));
    }

    #[test]
    fn key_matches_an_independent_sha256_computation() {
        let secret = b"known-hmac-secret".to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&secret);
        let digest: [u8; 32] = hasher.finalize().into();
        assert_eq!(derive_vault_key(&secret), digest);
    }
}
