//! The hardware boundary.
//!
//! [`VaultDevice`] isolates every USB/CTAP operation the flows need, so
//! [`crate::derive`] and [`crate::enroll`] stay pure logic and are exercised by the
//! functional test suite against a fake device. [`FidoKeyHidDevice`] is the real
//! transport for a Feitian BioPass.

use crate::config::{RP_ID, USER_DISPLAY_INITIAL, USER_ID, USER_NAME_INITIAL};
use crate::error::VaultError;
use ctap_hid_fido2::fidokey::{
    AssertionExtension, CredentialExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::{Cfg, FidoKeyHid, HidParam};

/// Feitian BioPass (USB), vendor id `0x096e`.
const FEITIAN_VID: u16 = 0x096e;

/// Feitian BioPass FIDO2 product id.
const BIO_PASS_PID: u16 = 0x085d;

/// Feitian All-in-Pass product id, the fallback model.
const ALL_IN_PASS_PID: u16 = 0x0866;

/// Credential type reported to the CTAP2 credential-management commands.
const CREDENTIAL_TYPE: &str = "public-key";

/// A resident credential stored on the vault authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    /// Credential id, the handle used by delete/rename.
    pub credential_id: Vec<u8>,
    /// User id handle the credential was registered with.
    pub user_id: Vec<u8>,
    /// User name as currently stored on the device.
    pub name: String,
    /// Display name as currently stored on the device.
    pub display_name: String,
}

/// Result of any [`VaultDevice`] call.
pub type DeviceResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The hardware operations the vault flows depend on.
pub trait VaultDevice {
    /// Resident credentials currently registered under the vault RP id.
    fn list_credentials(&self, pin: &str) -> DeviceResult<Vec<StoredCredential>>;

    /// Register a new discoverable hmac-secret credential; returns its id.
    fn create_credential(&self, pin: &str) -> DeviceResult<Vec<u8>>;

    /// Update the user name and display name of an existing credential.
    fn rename_credential(&self, pin: &str, credential_id: &[u8], name: &str) -> DeviceResult<()>;

    /// Remove an existing credential.
    fn delete_credential(&self, pin: &str, credential_id: &[u8]) -> DeviceResult<()>;

    /// Compute the on-device `HMAC-SHA-256(credRandom, salt)`.
    ///
    /// `pin` is `Some` on authenticators that require `pinUvAuth` for the
    /// hmac-secret extension; without it they answer `CTAP2_ERR_PIN_REQUIRED`.
    /// Supplying a PIN sets `uv = None`, so the fingerprint is not re-checked.
    fn hmac_secret(&self, salt_label: &str, pin: Option<&str>) -> DeviceResult<[u8; 32]>;
}

/// Real transport over USB HID for a Feitian BioPass.
pub struct FidoKeyHidDevice<'a> {
    device: &'a FidoKeyHid,
}

impl<'a> FidoKeyHidDevice<'a> {
    /// Wrap an already-opened [`FidoKeyHid`].
    pub fn new(device: &'a FidoKeyHid) -> Self {
        Self { device }
    }
}

impl VaultDevice for FidoKeyHidDevice<'_> {
    fn list_credentials(&self, pin: &str) -> DeviceResult<Vec<StoredCredential>> {
        let rps = self.device.credential_management_enumerate_rps(Some(pin))?;
        let Some(rp) = rps
            .iter()
            .find(|rp| rp.public_key_credential_rp_entity.id == RP_ID)
        else {
            return Ok(Vec::new());
        };

        let stored = self
            .device
            .credential_management_enumerate_credentials(Some(pin), &rp.rpid_hash)?
            .into_iter()
            .map(|credential| StoredCredential {
                credential_id: credential.public_key_credential_descriptor.id,
                user_id: credential.public_key_credential_user_entity.id,
                name: credential.public_key_credential_user_entity.name,
                display_name: credential.public_key_credential_user_entity.display_name,
            })
            .collect();

        Ok(stored)
    }

    fn create_credential(&self, pin: &str) -> DeviceResult<Vec<u8>> {
        let challenge = verifier::create_challenge();
        let user = PublicKeyCredentialUserEntity::new(
            Some(USER_ID),
            Some(USER_NAME_INITIAL),
            Some(USER_DISPLAY_INITIAL),
        );
        let args = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
            .resident_key()
            .extensions(&[CredentialExtension::HmacSecret(Some(true))])
            .user_entity(&user)
            .pin(pin)
            .build();

        let attestation = self.device.make_credential_with_args(&args)?;
        Ok(attestation.credential_descriptor.id)
    }

    fn rename_credential(&self, pin: &str, credential_id: &[u8], name: &str) -> DeviceResult<()> {
        let descriptor = descriptor(credential_id);
        let user = PublicKeyCredentialUserEntity::new(Some(USER_ID), Some(name), Some(name));
        self.device
            .credential_management_update_user_information(Some(pin), descriptor, user)?;
        Ok(())
    }

    fn delete_credential(&self, pin: &str, credential_id: &[u8]) -> DeviceResult<()> {
        self.device
            .credential_management_delete_credential(Some(pin), descriptor(credential_id))?;
        Ok(())
    }

    fn hmac_secret(&self, salt_label: &str, pin: Option<&str>) -> DeviceResult<[u8; 32]> {
        let salt = AssertionExtension::create_hmac_secret_from_string(salt_label);
        let challenge = verifier::create_challenge();
        let mut builder = GetAssertionArgsBuilder::new(RP_ID, &challenge).extensions(&[salt]);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        }
        let args = builder.build();

        let assertions = self.device.get_assertion_with_args(&args)?;
        let assertion = assertions
            .first()
            .ok_or(Box::new(VaultError::NoAssertion))?;

        let output = assertion
            .extensions
            .iter()
            .find_map(|extension| match extension {
                AssertionExtension::HmacSecret(Some(output)) => Some(*output),
                _ => None,
            })
            .ok_or(Box::new(VaultError::MissingHmacSecret))?;

        Ok(output)
    }
}

fn descriptor(credential_id: &[u8]) -> PublicKeyCredentialDescriptor {
    PublicKeyCredentialDescriptor {
        id: credential_id.to_vec(),
        ctype: CREDENTIAL_TYPE.to_string(),
    }
}

/// Open the first matching Feitian authenticator over USB HID.
///
/// The keep-alive "touch the sensor" prompt is enabled and routed to stderr, so
/// stdout stays a clean channel carrying only the derived key.
///
/// # Errors
/// The device is absent, unclaimed, or hidraw access is denied.
pub fn open_device() -> Result<FidoKeyHid, Box<dyn std::error::Error>> {
    let mut cfg = Cfg::init();
    cfg.enable_keep_alive_msg = true;
    cfg.keep_alive_msg_to_stderr = true;

    let params = [
        HidParam::VidPid {
            vid: FEITIAN_VID,
            pid: BIO_PASS_PID,
        },
        HidParam::VidPid {
            vid: FEITIAN_VID,
            pid: ALL_IN_PASS_PID,
        },
    ];

    Ok(FidoKeyHid::new(&params, &cfg)?)
}
