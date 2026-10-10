use ctap_hid_fido2::fidokey::{
    AssertionExtension, CredentialExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::{Cfg, FidoKeyHid, HidParam};
use sha2::{Digest, Sha256};
use std::process::exit;

const RP_ID: &str = "bitwarden-alternative.kevops";
const VAULT_SALT: &str = "kevops-vault-encryption-salt-xyz";
const USER_ID: &[u8] = b"kevops-vault-user";
const USER_NAME: &str = "kevops-vault";
const USER_DISPLAY: &str = "KevOps Vault";

/// Open the Feitian BioPass over USB HID.
/// The in-protocol "tap" keep-alive prompt is routed to stderr so that stdout
/// stays a clean channel for the derived key alone.
fn open_device() -> Result<FidoKeyHid, Box<dyn std::error::Error>> {
    let mut cfg = Cfg::init();
    cfg.enable_keep_alive_msg = true;
    cfg.keep_alive_msg_to_stderr = true;

    // 0x096e/0x085d = BioPass, 0x096e/0x0866 = All-in-Pass (fallback).
    Ok(FidoKeyHid::new(
        &[
            HidParam::VidPid {
                vid: 0x096e,
                pid: 0x085d,
            },
            HidParam::VidPid {
                vid: 0x096e,
                pid: 0x0866,
            },
        ],
        &cfg,
    )?)
}

/// Derive the 256-bit vault key from the on-device hmac-secret credential.
fn derive(device: &FidoKeyHid) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("⚡ Please tap the Feitian BioPass fingerprint sensor...");

    // The salt MUST be exactly 32 bytes; the label is hashed into place.
    let salt = AssertionExtension::create_hmac_secret_from_string(VAULT_SALT);

    // uv = Some(true) (builder default) forces on-device user verification — the
    // fingerprint. This call blocks until the finger is matched.
    let challenge = verifier::create_challenge();
    let args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .extensions(&[salt])
        .build();

    let assertions = device.get_assertion_with_args(&args)?;
    let assertion = assertions.first().ok_or(
        "no assertion returned by authenticator (is the device enrolled? run with `enroll`)",
    )?;

    // Pull the HMAC-SHA-256(credRandom, salt) output out of the extensions.
    let hmac_secret = assertion
        .extensions
        .iter()
        .find_map(|ext| match ext {
            AssertionExtension::HmacSecret(Some(output)) => Some(*output),
            _ => None,
        })
        .ok_or("authenticator returned no hmac-secret output (credential not registered with hmac-secret; run with `enroll`)")?;

    // Hash once more into a strict 32-byte AES-256 key.
    let mut hasher = Sha256::new();
    hasher.update(hmac_secret);
    let vault_decryption_key = hasher.finalize();

    let hex_key: String = vault_decryption_key
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    // stdout carries ONLY the 64-char hex key for clean piping / Command::output().
    eprintln!("🔓 Fingerprint verified! 256-bit Vault key derived.");
    print!("{}", hex_key);
    Ok(())
}

/// Register a dedicated, discoverable credential with the hmac-secret extension
/// enabled. This is the one-time enrollment the vault key derivation depends on.
fn enroll(device: &FidoKeyHid, pin: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("⚡ Enroll: tap the BioPass sensor to register the vault credential...");

    let challenge = verifier::create_challenge();
    let user =
        PublicKeyCredentialUserEntity::new(Some(USER_ID), Some(USER_NAME), Some(USER_DISPLAY));

    let mut builder = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
        .resident_key()
        .extensions(&[CredentialExtension::HmacSecret(Some(true))])
        .user_entity(&user);

    // If the authenticator requires a PIN for registration, supply it here.
    // (Passing a PIN sets uv = None; the fingerprint still gates later derives.)
    if let Some(pin) = pin {
        builder = builder.pin(pin);
    }
    let args = builder.build();

    let _attestation = device.make_credential_with_args(&args)?;
    eprintln!(
        "✅ Enrolled vault credential for RP '{}'. Run without arguments to derive the key.",
        RP_ID
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let device = open_device()?;
        match args.get(1).map(String::as_str) {
            Some("enroll") => {
                let pin = args
                    .iter()
                    .position(|a| a == "--pin")
                    .and_then(|i| args.get(i + 1))
                    .map(String::as_str);
                enroll(&device, pin)
            }
            Some(other) => {
                eprintln!("unknown subcommand: {}", other);
                eprintln!("usage: kevops-feitian-ufa-wrapper [enroll [--pin <pin>]]");
                Err("unknown subcommand".into())
            }
            None => derive(&device),
        }
    })();

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        exit(1);
    }
}
