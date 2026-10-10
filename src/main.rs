use ctap_hid_fido2::fidokey::{AssertionExtension, GetAssertionArgsBuilder};
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::{Cfg, FidoKeyHid, HidParam};
use sha2::{Digest, Sha256};

const RP_ID: &str = "bitwarden-alternative.kevops";
const VAULT_SALT: &str = "kevops-vault-encryption-salt-xyz";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Open the USB HID connection to the Feitian BioPass.
    //    new() walks the list and opens the first device that matches.
    //    0x096e/0x085d = BioPass, 0x096e/0x0866 = All-in-Pass (fallback).
    let device = FidoKeyHid::new(
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
        &Cfg::init(),
    )?;

    println!("⚡ Please tap the Feitian BioPass fingerprint sensor...");

    // 2. Build the hmac-secret extension input for this specific vault database.
    //    The salt MUST be exactly 32 bytes, so the label is hashed into place
    //    (a raw byte-string literal would not satisfy [u8; 32]).
    let salt = AssertionExtension::create_hmac_secret_from_string(VAULT_SALT);

    // 3. Ask the authenticator for the HMAC-Secret.
    //    uv = Some(true) (the builder default) is what forces on-device user
    //    verification — on the BioPass that is the fingerprint check. This call
    //    physically blocks until the finger is matched.
    let challenge = verifier::create_challenge();
    let args = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .extensions(&[salt])
        .build();

    let assertions = device.get_assertion_with_args(&args)?;
    let assertion = assertions.first().ok_or("no assertion returned by authenticator")?;

    // 4. Pull the decrypted CredRandom output out of the assertion extensions.
    let hmac_secret = assertion
        .extensions
        .iter()
        .find_map(|ext| match ext {
            AssertionExtension::HmacSecret(Some(output)) => Some(*output),
            _ => None,
        })
        .ok_or("authenticator returned no hmac-secret output (is the credential registered with hmac-secret enabled?)")?;

    // 5. Derive a strict 32-byte AES key.
    let mut hasher = Sha256::new();
    hasher.update(hmac_secret);
    let vault_decryption_key = hasher.finalize();

    // GenericArray has no LowerHex impl, so format the bytes explicitly.
    let hex_key: String = vault_decryption_key
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    println!(
        "🔓 Fingerprint verified! 256-bit Vault key derived: {}",
        hex_key
    );
    Ok(())
}
