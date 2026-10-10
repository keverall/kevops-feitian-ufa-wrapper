//! KevOps Feitian UFA wrapper — derive a deterministic AES-256 vault key from a
//! Feitian BioPass FIDO2 **hmac-secret** credential.
//!
//! The crate is split so every hardware-free rule is independently testable:
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`crate::config`] | Static on-device identity and salt label |
//! | [`crate::cli`] | Argument parsing into a `Command` |
//! | [`crate::device`] | `VaultDevice` transport boundary + real transport |
//! | [`crate::crypto`] | Key derivation and hex encoding (pure) |
//! | [`crate::naming`] | Sequential credential naming (pure) |
//! | [`crate::derive`] | Key derivation flow |
//! | [`crate::enroll`] | Credential enrolment flow |
//! | [`crate::error`] | `VaultError` with user-facing messages |
//!
//! Only [`device`] touches USB; `derive` and `enroll` depend on the
//! [`device::VaultDevice`] trait, so the functional test suite runs them against a
//! fake device with no hardware.

#![forbid(unsafe_code)]
#![cfg_attr(doc, warn(missing_docs))]

pub mod cli;
pub mod config;
pub mod crypto;
pub mod derive;
pub mod device;
pub mod enroll;
pub mod error;
pub mod naming;

pub use device::{FidoKeyHidDevice, open_device};
pub use error::VaultError;
