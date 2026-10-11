//! Enrolment flow: register, sequentially name, and optionally replace a credential.

use crate::device::{StoredCredential, VaultDevice};
use crate::error::VaultError;
use crate::naming::{first_credential_name, is_vault_name, next_credential_name};

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
/// when replacing, remove only the previous *vault* credentials — and only after
/// the new credential is confirmed.
///
/// Credentials that do not carry the vault name prefix are never deleted: they
/// belong to something else that happens to share the RP id.
///
/// Returns the assigned credential name.
///
/// # Errors
/// [`VaultError::Device`] when the transport or a CTAP call fails,
/// [`VaultError::NoReplaceableCredential`] when a replace was requested but no
/// vault credential exists, and [`VaultError::CredentialCounterExhausted`] when
/// the naming counter is exhausted.
pub fn enroll_vault_credential(
    device: &dyn VaultDevice,
    pin: &str,
    policy: ReplacePolicy,
) -> Result<String, VaultError> {
    let existing = device.list_credentials(pin).map_err(VaultError::device)?;

    let replace = replace_decision(&policy, &existing);
    let name = credential_name(replace, &existing)?;
    let deletable = replaceable(existing.iter());

    let credential_id = device.create_credential(pin).map_err(VaultError::device)?;
    device
        .rename_credential(pin, &credential_id, &name)
        .map_err(VaultError::device)?;

    // Safety ordering: the new credential exists and is named before anything is
    // deleted, so a failure mid-replace never leaves the vault without a key.
    // Deletion is not atomic: a failure stops the loop and leaves the already
    // deleted credentials gone, which is why the new one is named first.
    if replace {
        for credential in deletable {
            device
                .delete_credential(pin, &credential.credential_id)
                .map_err(VaultError::device)?;
        }
    }

    Ok(name)
}

/// Delete only credentials owned by this tool after an explicit confirmation.
///
/// The confirmation callback receives the filtered credentials before any
/// deletion. Returning `false` performs no mutation and returns an empty list.
/// Deletion is best-effort and stops at the first device error.
///
/// # Errors
/// [`VaultError::Device`] when listing or deleting credentials fails.
pub fn delete_vault_credentials<F>(
    device: &dyn VaultDevice,
    pin: &str,
    confirm: F,
) -> Result<Vec<String>, VaultError>
where
    F: FnOnce(&[StoredCredential]) -> bool,
{
    let existing = device.list_credentials(pin).map_err(VaultError::device)?;
    let owned: Vec<StoredCredential> = replaceable(existing.iter()).cloned().collect();
    if !confirm(&owned) {
        return Ok(Vec::new());
    }

    let mut deleted = Vec::with_capacity(owned.len());
    for credential in owned {
        device
            .delete_credential(pin, &credential.credential_id)
            .map_err(VaultError::device)?;
        deleted.push(credential.name);
    }
    Ok(deleted)
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
fn credential_name(replace: bool, existing: &[StoredCredential]) -> Result<String, VaultError> {
    if replace {
        return Ok(first_credential_name());
    }
    let names: Vec<&str> = existing
        .iter()
        .map(|credential| credential.name.as_str())
        .collect();
    next_credential_name(&names)
}

/// The credentials a replace may delete: vault ones only.
fn replaceable<'a>(
    existing: impl Iterator<Item = &'a StoredCredential>,
) -> impl Iterator<Item = &'a StoredCredential> {
    existing.filter(|credential| is_vault_name(&credential.name))
}
