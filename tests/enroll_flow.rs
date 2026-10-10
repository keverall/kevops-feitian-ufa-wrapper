//! Functional tests for the enrolment flow against a fake device.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{CREATED_CREDENTIAL_ID, FakeDevice, RecordedCall, credential};
use kevops_feitian_ufa_wrapper::config::CREDENTIAL_NAME_PREFIX;
use kevops_feitian_ufa_wrapper::enroll::{ReplacePolicy, enroll_vault_credential};

fn wrapper(counter: u32) -> String {
    format!("{CREDENTIAL_NAME_PREFIX}{counter:02}")
}

#[test]
fn first_enrolment_is_named_with_counter_one_and_creates_only() {
    let device = FakeDevice::new();

    let name = enroll_vault_credential(&device, "123456", ReplacePolicy::AlwaysAdd)
        .expect("enrols on an empty device");

    assert_eq!(name, wrapper(1));
    assert_eq!(
        device.calls(),
        vec![
            RecordedCall::Create,
            RecordedCall::Rename {
                credential_id: CREATED_CREDENTIAL_ID.to_vec(),
                name: wrapper(1),
            },
        ]
    );
}

#[test]
fn adding_continues_the_ascending_sequence() {
    let existing = vec![credential(&wrapper(1)), credential(&wrapper(2))];
    let device = FakeDevice::new().with_existing(existing);

    let name = enroll_vault_credential(&device, "123456", ReplacePolicy::AlwaysAdd)
        .expect("enrols alongside existing credentials");

    assert_eq!(name, wrapper(3));
    assert!(
        !device
            .calls()
            .iter()
            .any(|call| matches!(call, RecordedCall::Delete { .. })),
        "adding must never delete"
    );
}

#[test]
fn foreign_credentials_fall_back_to_counter_one() {
    let device = FakeDevice::new().with_existing(vec![credential("bitwarden-login")]);

    let name = enroll_vault_credential(&device, "123456", ReplacePolicy::AlwaysAdd)
        .expect("enrols next to a foreign credential");

    assert_eq!(name, wrapper(1));
}

#[test]
fn replacing_restarts_at_one_and_deletes_the_old_credentials_last() {
    let existing = vec![credential(&wrapper(1)), credential(&wrapper(2))];
    let device = FakeDevice::new().with_existing(existing);

    let name = enroll_vault_credential(&device, "123456", ReplacePolicy::AlwaysReplace)
        .expect("replaces the existing credentials");

    assert_eq!(name, wrapper(1));
    assert_eq!(
        device.calls(),
        vec![
            RecordedCall::Create,
            RecordedCall::Rename {
                credential_id: CREATED_CREDENTIAL_ID.to_vec(),
                name: wrapper(1),
            },
            RecordedCall::Delete {
                credential_id: b"id-kevops-feitan-ufa-passwordless-wrapper01".to_vec()
            },
            RecordedCall::Delete {
                credential_id: b"id-kevops-feitan-ufa-passwordless-wrapper02".to_vec()
            },
        ],
        "the new credential must be created and renamed before any delete"
    );
}

#[test]
fn asking_delegates_the_replace_decision() {
    let existing = vec![credential(&wrapper(1))];

    let adding = FakeDevice::new().with_existing(existing.clone());
    let name = enroll_vault_credential(&adding, "123456", ReplacePolicy::Ask(Box::new(|_| false)))
        .expect("asks and adds");
    assert_eq!(name, wrapper(2));

    let replacing = FakeDevice::new().with_existing(existing);
    let name =
        enroll_vault_credential(&replacing, "123456", ReplacePolicy::Ask(Box::new(|_| true)))
            .expect("asks and replaces");
    assert_eq!(name, wrapper(1));
    assert_eq!(
        replacing.calls().last(),
        Some(&RecordedCall::Delete {
            credential_id: b"id-kevops-feitan-ufa-passwordless-wrapper01".to_vec()
        })
    );
}

#[test]
fn an_empty_device_skips_the_prompt_entirely() {
    let device = FakeDevice::new();
    // `AlwaysReplace` on an empty device must not delete anything.
    let name = enroll_vault_credential(&device, "123456", ReplacePolicy::AlwaysReplace)
        .expect("enrols on an empty device");

    assert_eq!(name, wrapper(1));
    assert!(
        !device
            .calls()
            .iter()
            .any(|call| matches!(call, RecordedCall::Delete { .. }))
    );
}

#[test]
fn a_transport_failure_leaves_nothing_deleted() {
    let device = FakeDevice::new().with_failure("device gone");

    let error = enroll_vault_credential(&device, "123456", ReplacePolicy::AlwaysReplace)
        .expect_err("a failing device is an error");

    assert_eq!(error.to_string(), "device gone");
    assert!(
        device.calls().is_empty(),
        "no call should reach the fake after the first failure"
    );
}

#[test]
fn a_failure_while_renaming_stops_before_any_delete() {
    let device = FakeDevice::new().with_existing(vec![credential(&wrapper(1))]);
    // Creation succeeds; renaming fails.
    let device = RenameFailingDevice::new(device);

    let error = enroll_vault_credential(&device, "123456", ReplacePolicy::AlwaysReplace)
        .expect_err("a failing rename is an error");

    assert_eq!(error.to_string(), "rename failed");
    assert!(
        !device
            .calls()
            .iter()
            .any(|call| matches!(call, RecordedCall::Delete { .. })),
        "the new credential must be fully named before any delete"
    );
}

/// Wraps [`FakeDevice`] and fails only on `rename_credential`.
struct RenameFailingDevice {
    inner: FakeDevice,
}

impl RenameFailingDevice {
    fn new(inner: FakeDevice) -> Self {
        Self { inner }
    }

    fn calls(&self) -> Vec<RecordedCall> {
        self.inner.calls()
    }
}

impl kevops_feitian_ufa_wrapper::device::VaultDevice for RenameFailingDevice {
    fn list_credentials(
        &self,
        pin: &str,
    ) -> kevops_feitian_ufa_wrapper::device::DeviceResult<
        Vec<kevops_feitian_ufa_wrapper::device::StoredCredential>,
    > {
        self.inner.list_credentials(pin)
    }
    fn create_credential(
        &self,
        pin: &str,
    ) -> kevops_feitian_ufa_wrapper::device::DeviceResult<Vec<u8>> {
        self.inner.create_credential(pin)
    }
    fn rename_credential(
        &self,
        _pin: &str,
        _id: &[u8],
        _name: &str,
    ) -> kevops_feitian_ufa_wrapper::device::DeviceResult<()> {
        Err("rename failed".into())
    }
    fn delete_credential(
        &self,
        pin: &str,
        id: &[u8],
    ) -> kevops_feitian_ufa_wrapper::device::DeviceResult<()> {
        self.inner.delete_credential(pin, id)
    }
    fn hmac_secret(
        &self,
        salt_label: &str,
        pin: Option<&str>,
    ) -> kevops_feitian_ufa_wrapper::device::DeviceResult<[u8; 32]> {
        self.inner.hmac_secret(salt_label, pin)
    }
}
