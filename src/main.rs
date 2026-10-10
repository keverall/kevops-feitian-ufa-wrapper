use ctap_hid_fido2::fidokey::{
    AssertionExtension, CredentialExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::{Cfg, FidoKeyHid, HidParam};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::process::exit;

const RP_ID: &str = "bitwarden-alternative.kevops";
const VAULT_SALT: &str = "kevops-vault-encryption-salt-xyz";
const USER_ID: &[u8] = b"kevops-vault-user";
const USER_NAME: &str = "kevops-vault";
const USER_DISPLAY: &str = "KevOps Vault";

/// Sequential display-name prefix for enrolled vault credentials.
/// The suffix is zero-padded ascending: wrapper01, wrapper02, wrapper03, ...
const CRED_NAME_PREFIX: &str = "kevops-feitan-ufa-passwordless-wrapper";

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

/// Register (and optionally replace) a dedicated, discoverable credential with the
/// hmac-secret extension enabled, then rename it to a sequential `wrapperNN` label.
///
/// Credential management (enumerate / delete / rename) requires PIN auth, so `pin`
/// is mandatory for this subcommand.
fn enroll(device: &FidoKeyHid, pin: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Discover any credentials already registered under our RP.
    let rps = device.credential_management_enumerate_rps(Some(pin))?;
    let existing_creds: Vec<_> = match rps
        .iter()
        .find(|rp| rp.public_key_credential_rp_entity.id == RP_ID)
    {
        Some(rp) => device.credential_management_enumerate_credentials(Some(pin), &rp.rpid_hash)?,
        None => Vec::new(),
    };

    // 2. If one exists, ask whether to replace it or add another.
    let mut replace_existing = false;
    if !existing_creds.is_empty() {
        eprintln!(
            "ℹ️ Found {} existing vault credential(s) for RP '{}'.",
            existing_creds.len(),
            RP_ID
        );
        eprint!("   Replace existing (R) or add a new one (A)? [R/A]: ");
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        // Explicit "R" replaces; anything else (including Enter) adds.
        replace_existing = input.trim().eq_ignore_ascii_case("R");
        eprintln!(
            "   -> {}",
            if replace_existing {
                "replacing existing credential(s)"
            } else {
                "adding a new credential"
            }
        );
    }

    // 3. Decide the sequential name. Replacing restarts at 01; adding continues
    //    the ascending sequence parsed from existing wrapperNN labels.
    let next_nn = if replace_existing {
        1
    } else {
        let mut max = 0u32;
        for c in &existing_creds {
            let parsed = c
                .public_key_credential_user_entity
                .name
                .strip_prefix(CRED_NAME_PREFIX)
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(n) = parsed {
                max = max.max(n);
            }
        }
        max + 1
    };

    // 4. Create the discoverable hmac-secret credential.
    eprintln!("⚡ Enroll: tap the BioPass sensor to register the vault credential...");
    let challenge = verifier::create_challenge();
    let user =
        PublicKeyCredentialUserEntity::new(Some(USER_ID), Some(USER_NAME), Some(USER_DISPLAY));
    let args = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
        .resident_key()
        .extensions(&[CredentialExtension::HmacSecret(Some(true))])
        .user_entity(&user)
        .pin(pin)
        .build();

    let attestation = device.make_credential_with_args(&args)?;
    let new_descriptor = attestation.credential_descriptor;

    // 5. Rename the just-created credential to its sequential wrapperNN label.
    //    Keep the same user.id handle; only the name/display name change.
    let new_name = format!("{}{:02}", CRED_NAME_PREFIX, next_nn);
    let renamed =
        PublicKeyCredentialUserEntity::new(Some(USER_ID), Some(&new_name), Some(&new_name));
    device.credential_management_update_user_information(Some(pin), new_descriptor, renamed)?;

    // 6. Only after the new credential is confirmed do we drop the old ones (replace).
    if replace_existing {
        for c in existing_creds {
            device.credential_management_delete_credential(
                Some(pin),
                c.public_key_credential_descriptor,
            )?;
        }
    }

    eprintln!(
        "✅ Enrolled vault credential '{}' for RP '{}'. Run without arguments to derive the key.",
        new_name, RP_ID
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
                match pin {
                    Some(p) => enroll(&device, p),
                    None => {
                        eprintln!(
                            "enroll requires a PIN: kevops-feitian-ufa-wrapper enroll --pin <pin>"
                        );
                        Err("missing --pin".into())
                    }
                }
            }
            Some(other) => {
                eprintln!("unknown subcommand: {}", other);
                eprintln!("usage: kevops-feitian-ufa-wrapper [enroll --pin <pin>]");
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
