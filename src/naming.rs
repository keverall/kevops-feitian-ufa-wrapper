//! Sequential naming of enrolled vault credentials: `<PREFIX>01`, `<PREFIX>02`, ...

use crate::config::{CREDENTIAL_NAME_PREFIX, USER_NAME_INITIAL};
use crate::error::VaultError;

/// Width of the zero-padded credential counter.
const COUNTER_WIDTH: usize = 2;

/// The name of the first vault credential (`<PREFIX>01`).
pub fn first_credential_name() -> String {
    padded(1)
}

/// Whether `name` is a vault credential name produced by this tool.
///
/// Only credentials this tool created are renamed or deleted; foreign
/// credentials sharing the RP id must survive a replace.
pub fn is_vault_name(name: &str) -> bool {
    name == USER_NAME_INITIAL || name.starts_with(CREDENTIAL_NAME_PREFIX)
}

/// The next sequential name given the names already on the authenticator.
///
/// Names that do not match the prefix, or whose counter does not parse, are
/// ignored so foreign credentials never skew the sequence.
///
/// # Errors
/// [`VaultError::CredentialCounterExhausted`] when the counter has no successor,
/// which is only reachable at `u32::MAX`.
pub fn next_credential_name(existing: &[&str]) -> Result<String, VaultError> {
    let next = highest_counter(existing)
        .checked_add(1)
        .ok_or(VaultError::CredentialCounterExhausted)?;
    Ok(padded(next))
}

/// The counter encoded in `<PREFIX>nn`, if the name matches and parses.
pub fn counter_of(name: &str) -> Option<u32> {
    name.strip_prefix(CREDENTIAL_NAME_PREFIX)?.parse().ok()
}

fn highest_counter(existing: &[&str]) -> u32 {
    existing
        .iter()
        .filter_map(|name| counter_of(name))
        .max()
        .unwrap_or(0)
}

fn padded(counter: u32) -> String {
    format!("{CREDENTIAL_NAME_PREFIX}{counter:0COUNTER_WIDTH$}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CREDENTIAL_NAME_PREFIX, USER_NAME_INITIAL};

    #[test]
    fn first_name_is_zero_padded_to_two_digits() {
        assert_eq!(
            first_credential_name(),
            format!("{CREDENTIAL_NAME_PREFIX}01")
        );
    }

    #[test]
    fn sequence_continues_from_the_highest_existing_counter() {
        let existing = [
            format!("{CREDENTIAL_NAME_PREFIX}01"),
            format!("{CREDENTIAL_NAME_PREFIX}02"),
        ];
        let names: Vec<&str> = existing.iter().map(String::as_str).collect();
        assert_eq!(
            next_credential_name(&names).unwrap(),
            format!("{CREDENTIAL_NAME_PREFIX}03")
        );
    }

    #[test]
    fn gaps_do_not_reuse_numbers() {
        let existing = [format!("{CREDENTIAL_NAME_PREFIX}07")];
        let names: Vec<&str> = existing.iter().map(String::as_str).collect();
        assert_eq!(
            next_credential_name(&names).unwrap(),
            format!("{CREDENTIAL_NAME_PREFIX}08")
        );
    }

    #[test]
    fn foreign_names_fall_back_to_one() {
        let names = ["bitwarden-login", "cachyos-host"];
        assert_eq!(
            next_credential_name(&names).unwrap(),
            format!("{CREDENTIAL_NAME_PREFIX}01")
        );
    }

    #[test]
    fn empty_inventory_starts_at_one() {
        assert_eq!(
            next_credential_name(&[]).unwrap(),
            format!("{CREDENTIAL_NAME_PREFIX}01")
        );
    }

    #[test]
    fn three_digit_counters_widen_naturally() {
        let existing = [format!("{CREDENTIAL_NAME_PREFIX}099")];
        let names: Vec<&str> = existing.iter().map(String::as_str).collect();
        assert_eq!(
            next_credential_name(&names).unwrap(),
            format!("{CREDENTIAL_NAME_PREFIX}100")
        );
    }

    #[test]
    fn counter_exhaustion_is_an_error_not_a_wraparound() {
        let exhausted = format!("{CREDENTIAL_NAME_PREFIX}{}", u32::MAX);
        assert_eq!(
            next_credential_name(&[&exhausted]),
            Err(VaultError::CredentialCounterExhausted)
        );
    }

    #[test]
    fn only_names_with_the_vault_prefix_are_ours() {
        assert!(is_vault_name(&format!("{CREDENTIAL_NAME_PREFIX}01")));
        assert!(is_vault_name(USER_NAME_INITIAL));
        assert!(!is_vault_name("bitwarden-login"));
        assert!(!is_vault_name(&format!("other-{CREDENTIAL_NAME_PREFIX}01")));
    }

    #[test]
    fn non_numeric_suffix_is_ignored() {
        assert_eq!(counter_of(&format!("{CREDENTIAL_NAME_PREFIX}abc")), None);
        assert_eq!(counter_of(&format!("{CREDENTIAL_NAME_PREFIX}xy")), None);
        assert_eq!(counter_of("unrelated"), None);
        assert_eq!(counter_of(&format!("{CREDENTIAL_NAME_PREFIX}12")), Some(12));
    }
}
