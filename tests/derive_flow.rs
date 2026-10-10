//! Functional tests for the derive flow against a fake device.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::FakeDevice;
use kevops_feitian_ufa_wrapper::crypto;
use kevops_feitian_ufa_wrapper::derive;
use kevops_feitian_ufa_wrapper::error::VaultError;

use common::expected_key;

const SALT_LABEL: &str = "kevops-vault-encryption-salt-xyz";

#[test]
fn derives_the_key_from_the_on_device_secret() {
    let secret = [0x42u8; 32];
    let device = FakeDevice::new().with_hmac_secret(secret);

    let key = derive::derive_vault_key(&device, SALT_LABEL, None).expect("derives the key");

    assert_eq!(key, expected_key(secret));
    assert_eq!(key.len(), crypto::VAULT_KEY_SIZE);
}

#[test]
fn prints_exactly_64_hex_characters() {
    let device = FakeDevice::new().with_hmac_secret([0u8; 32]);
    let key = derive::derive_vault_key(&device, SALT_LABEL, None).expect("derives the key");

    let encoded = crypto::encode_key(&key);
    assert_eq!(encoded.len(), crypto::HEX_KEY_LENGTH);
    assert!(
        encoded
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    );
}

#[test]
fn the_same_secret_always_derives_the_same_key() {
    let secret = [0x99u8; 32];
    let first = derive::derive_vault_key(
        &FakeDevice::new().with_hmac_secret(secret),
        SALT_LABEL,
        None,
    )
    .unwrap();
    let second = derive::derive_vault_key(
        &FakeDevice::new().with_hmac_secret(secret),
        SALT_LABEL,
        None,
    )
    .unwrap();
    assert_eq!(first, second);
}

#[test]
fn a_missing_secret_is_surfaced_as_a_device_error() {
    let device = FakeDevice::new();
    let error =
        derive::derive_vault_key(&device, SALT_LABEL, None).expect_err("no secret is an error");
    assert_eq!(error, VaultError::device("no hmac secret configured"));
}
