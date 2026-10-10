//! Static configuration: the vault's on-device identity and salt label.
//!
//! Changing [`RP_ID`] or [`SALT_LABEL`] changes the derived key and strands any
//! credential already enrolled under the previous values.

/// Relying Party id the vault credential is registered and asserted under.
pub const RP_ID: &str = "bitwarden-alternative.kevops";

/// Human label hashed into the 32-byte hmac-secret salt (domain separation).
///
/// The CTAP2 `hmac-secret` extension requires an exactly-32-byte salt; the crate
/// relies on `create_hmac_secret_from_string`, which hashes this label into one.
pub const SALT_LABEL: &str = "kevops-vault-encryption-salt-xyz";

/// Stable user.id handle registered with the vault credential.
pub const USER_ID: &[u8] = b"kevops-vault-user";

/// User name registered at credential creation, before the sequential rename.
pub const USER_NAME_INITIAL: &str = "kevops-vault";

/// Display name registered at credential creation, before the sequential rename.
pub const USER_DISPLAY_INITIAL: &str = "KevOps Vault";

/// Prefix of the sequential credential names: `<PREFIX>01`, `<PREFIX>02`, ...
///
/// Spelled as specified by the project owner. It is a credential *label* only and
/// does not affect the derived key.
pub const CREDENTIAL_NAME_PREFIX: &str = "kevops-feitan-ufa-passwordless-wrapper";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_label_is_hashed_to_the_required_32_bytes() {
        // The label itself is arbitrary; the 32-byte requirement is satisfied by
        // `create_hmac_secret_from_string`, asserted indirectly in `crypto` tests.
        assert!(!SALT_LABEL.is_empty());
    }

    #[test]
    fn credential_name_prefix_is_usable_as_a_strip_prefix() {
        // The sequential naming relies on this prefix being an exact match target.
        assert!(CREDENTIAL_NAME_PREFIX.ends_with("wrapper"));
        assert!(format!("{CREDENTIAL_NAME_PREFIX}01").starts_with(CREDENTIAL_NAME_PREFIX));
    }

    #[test]
    fn user_id_is_stable() {
        assert_eq!(USER_ID, b"kevops-vault-user");
    }
}
