//! Shared double for the functional test suite: a [`VaultDevice`] that records calls.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)] // each test binary uses a different subset of these helpers

use kevops_feitian_ufa_wrapper::crypto::derive_vault_key;
use kevops_feitian_ufa_wrapper::device::{DeviceResult, StoredCredential, VaultDevice};
use std::cell::RefCell;

/// Calls issued to [`FakeDevice`], in order. Order is what the replace safety
/// guarantee is about, so the tests assert on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedCall {
    /// A credential was created.
    Create,
    /// A credential was renamed.
    Rename {
        credential_id: Vec<u8>,
        name: String,
    },
    /// A credential was deleted.
    Delete { credential_id: Vec<u8> },
}

/// Credential id handed out by [`FakeDevice::create_credential`].
pub const CREATED_CREDENTIAL_ID: &[u8] = b"created-credential-id";

/// An in-memory [`VaultDevice`].
#[derive(Default)]
pub struct FakeDevice {
    existing: Vec<StoredCredential>,
    hmac_secret: Option<[u8; 32]>,
    failure: Option<String>,
    calls: RefCell<Vec<RecordedCall>>,
}

impl FakeDevice {
    /// A device with no credentials and no hmac secret configured.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-load the credentials reported by `list_credentials`.
    pub fn with_existing(mut self, existing: Vec<StoredCredential>) -> Self {
        self.existing = existing;
        self
    }

    /// Configure the hmac-secret output.
    pub fn with_hmac_secret(mut self, hmac_secret: [u8; 32]) -> Self {
        self.hmac_secret = Some(hmac_secret);
        self
    }

    /// Make every call fail with this message.
    pub fn with_failure(mut self, message: &str) -> Self {
        self.failure = Some(message.to_string());
        self
    }

    /// Every call made so far, in order.
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.borrow().clone()
    }

    fn failure(&self) -> DeviceResult<()> {
        match &self.failure {
            Some(message) => Err(message.as_str().into()),
            None => Ok(()),
        }
    }
}

impl VaultDevice for FakeDevice {
    fn list_credentials(&self, _pin: &str) -> DeviceResult<Vec<StoredCredential>> {
        self.failure()?;
        Ok(self.existing.clone())
    }

    fn create_credential(&self, _pin: &str) -> DeviceResult<Vec<u8>> {
        self.failure()?;
        self.calls.borrow_mut().push(RecordedCall::Create);
        Ok(CREATED_CREDENTIAL_ID.to_vec())
    }

    fn rename_credential(&self, _pin: &str, credential_id: &[u8], name: &str) -> DeviceResult<()> {
        self.failure()?;
        self.calls.borrow_mut().push(RecordedCall::Rename {
            credential_id: credential_id.to_vec(),
            name: name.to_string(),
        });
        Ok(())
    }

    fn delete_credential(&self, _pin: &str, credential_id: &[u8]) -> DeviceResult<()> {
        self.failure()?;
        self.calls.borrow_mut().push(RecordedCall::Delete {
            credential_id: credential_id.to_vec(),
        });
        Ok(())
    }

    fn hmac_secret(&self, _salt_label: &str, _pin: Option<&str>) -> DeviceResult<[u8; 32]> {
        self.failure()?;
        self.hmac_secret
            .ok_or_else(|| "no hmac secret configured".into())
    }
}

/// Build a [`StoredCredential`] with derived ids and a given display name.
pub fn credential(name: &str) -> StoredCredential {
    StoredCredential {
        credential_id: format!("id-{name}").into_bytes(),
        user_id: b"kevops-vault-user".to_vec(),
        name: name.to_string(),
        display_name: name.to_string(),
    }
}

/// The key the derive flow must produce for a given secret.
pub fn expected_key(secret: [u8; 32]) -> [u8; 32] {
    derive_vault_key(&secret)
}
