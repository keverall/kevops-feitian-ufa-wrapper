//! Enrolment flow: register, sequentially name, and optionally replace a credential.

use crate::device::{StoredCredential, VaultDevice};
use crate::error::VaultError;
use crate::naming::{first_credential_name, next_credential_name};

/// The answer to "should the existing credentials be replaced?".
pub type ReplaceDecision = Box<dyn Fn(&[StoredCredential]) -> bool>;

/// How to resolve credentials that already exist for the vault RP id.
pub enum ReplacePolicy {
    /// Keep existing credentials and add another.
    AlwaysAdd,
    /// Delete all existing vault credentials once the new one is confirmed.
    AlwaysReplace,
    /// Ask `policy`; it receives the existing credentials and answers `true` to replace.
    Ask(ReplaceDecision),
}

/// Register a new discoverable hmac-secret credential, name it sequentially, and,
/// when replacing, remove the previous ones only after the new credential is
/// confirmed.
///
/// Returns the assigned credential name.
///
/// # Errors
/// [`VaultError::Device`] when the transport or a CTAP call fails.
pub fn enroll_vault_credential(
    device: &dyn VaultDevice,
    pin: &str,
    policy: ReplacePolicy,
) -> Result<String, VaultError> {
    let existing = device.list_credentials(pin).map_err(VaultError::device)?;

    let replace = replace_decision(&policy, &existing);
    let name = credential_name(replace, &existing);

    let credential_id = device.create_credential(pin).map_err(VaultError::device)?;
    device
        .rename_credential(pin, &credential_id, &name)
        .map_err(VaultError::device)?;

    // Safety ordering: the new credential exists and is named before anything is
    // deleted, so a failure mid-replace never leaves the vault without a key.
    if replace {
        for credential in &existing {
            device
                .delete_credential(pin, &credential.credential_id)
                .map_err(VaultError::device)?;
        }
    }

    Ok(name)
}

fn replace_decision(policy: &ReplacePolicy, existing: &[StoredCredential]) -> bool {
    if existing.is_empty() {
        return false;
    }
    match policy {
        ReplacePolicy::AlwaysAdd => false,
        ReplacePolicy::AlwaysReplace => true,
        ReplacePolicy::Ask(ask) => ask(existing),
    }
}

/// Replacing restarts the sequence at `01`; adding continues it.
fn credential_name(replace: bool, existing: &[StoredCredential]) -> String {
    if replace {
        return first_credential_name();
    }
    let names: Vec<&str> = existing
        .iter()
        .map(|credential| credential.name.as_str())
        .collect();
    next_credential_name(&names)
}
