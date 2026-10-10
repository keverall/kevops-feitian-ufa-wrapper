# Architecture — Feitian UFA wrapper

This document explains *how* the vault key is produced and enrolment is managed,
independently of the Feitian hardware. It is the durable companion to the
high-level diagram in [`../README.md`](../README.md#architecture).

## 1. The transport boundary

Only `src/device.rs` imports `ctap-hid-fido2`. Everything above it works against
an interface, which is what makes the flows fully testable without a BioPass.

```
        ┌────────────────────────────┐
        │  src/main.rs  (thin CLI)   │  parse + present only
        └─────────────┬──────────────┘
                      │  &dyn VaultDevice
                      ▼
        ┌────────────────────────────┐
        │  src/derive.rs            │   derive_vault_key(device, salt, pin)
        │  src/enroll.rs            │   enroll_vault_credential(device, pin, policy)
        └─────────────┬──────────────┘
                      │  trait method call
                      ▼
        ┌────────────────────────────┐
        │  src/device.rs            │
        │   ┌─ trait VaultDevice    │   1) list_credentials(pin)
        │   │    create_credential   │   2) create_credential(pin) -> id
        │   │    rename_credential   │   3) rename_credential(pin, id, name)
        │   │    delete_credential   │   4) delete_credential(pin, id)
        │   │    hmac_secret(..)     │   5) hmac_secret(salt, pin) -> [u8;32]
        │   └─ struct FidoKeyHidDevice│
        └─────────────┬──────────────┘
                      │  gets/assert + cred-mgmt (ctap-hid-fido2 3.6.0)
                      ▼
        Feitian BioPass  0x096e:085d / 0x0866   (USB HID)
```

`open_device()` lives here too and configures `Cfg` exactly once:
`enable_keep_alive_msg = true` with `keep_alive_msg_to_stderr = true`, so the
in-protocol "touch the sensor" prompt is routed to `stderr` and `stdout` stays a
clean key channel.

## 2. Derive flow

`cargo run --release [--pin <pin>]` → `Command::Derive { pin }` → `print_vault_key`.

```text
1. open_device()
   eprintln("⚡ tap the sensor …")                ──► stderr
2. derive::derive_vault_key(device, SALT_LABEL, pin)
   . device.hmac_secret(SALT_LABEL, pin)
       salt = create_hmac_secret_from_string("kevops-vault-encryption-salt-xyz")
       → AssertionExtension::HmacSecret               (32-byte salt, domain-separated)
       uv = true (fingerprint)    OR   pinUvAuth if --pin  (sets uv = None)
   . crypto::derive_vault_key(hmac_secret)
       SHA-256(hmac_secret) → [u8; 32] AES-256 key
3. eprintln("🔓 Fingerprint verified …")          ──► stderr
4. print!("{:02x}", key)                           ──► stdout: 64 hex chars ONLY
```

**Why a PIN is optional but sometimes mandatory.** The BioPass answers
`CTAP2_ERR_PIN_REQUIRED` (0x36) for the hmac-secret extension when the
credential/policy requires `pinUvAuth`. Supplying `--pin` satisfies that, but per
CTAP 2.1 §12.5 it sets `uv = None`, so the **fingerprint no longer gates
derivation**. Prefer a credential whose UV is enforced in hardware; fall back to
`--pin` only where the authenticator demands it. (Exit-code `1`, key still
printed only on success.)

## 3. Enrolment flow (R/A, replace, rename, delete)

`cargo run --release -- enroll --pin <pin>` → `Command::Enroll { pin }` →
`enroll_credential` → `enroll::enroll_vault_credential(device, pin, policy)`.

```text
1. existing = device.list_credentials(pin)     // credential-management enumerate
2. ask the user (default R=replaces, A=adds)   // only when existing is non-empty
3. next_nn =  if replace { 1 } else { max(counter_of(names)) + 1 }
4. id   = device.create_credential(pin)        ──► RecordedCall::Create
5.      = device.rename_credential(pin, id, "wrapperNN")  ──► RecordedCall::Rename
6. if replace:
       for c in existing: device.delete_credential(pin, c.credential_id)  ──► Delete…
```

### 3.1 The ordering invariant

The new credential is **created and renamed before any old credential is deleted**.
This is not incidental — it is the single safety property the flow guarantees:

| Step | State of "vault credential for the RP" |
|---|---|
| after `1` | the previous N credentials (if any) |
| after `4` | previous N **plus** the new, unnamed one |
| after `5` | previous N **plus** the new one, now named `wrapperNN` |
| during `6` | count goes N+1 → N (only after step 5 is confirmed) |

Consequences covered by `tests/enroll_flow.rs`:

- `replacing_restarts_at_one_and_deletes_the_old_credentials_last` — asserts the
  call sequence is exactly `Create → Rename → Delete…` (in that order).
- `a_failure_while_renaming_stops_before_any_delete` — if `rename` fails, **zero**
  deletes are recorded, so the old credentials are left in place.
- `an_empty_device_skips_the_prompt_entirely` — an empty device never deletes.

## 4. Naming scheme

`- kevitops-feitan-ufa-passwordless-wrapperNN`, zero-padded, ascending (`01`,
`02`, `…`, `099`, `100`). `next_credential_name`:

1. strips the prefix `kevops-feitan-ufa-passwordless-wrapper` from every
   existing credential's user name;
2. parses the remainder as `u32` (non-numeric suffixes are ignored, so
   *foreign* credentials like `bitwarden-login` can never skew the sequence);
3. takes the max and adds 1 (or starts at `1` for `replace` / empty inventory).

## 5. Configuration reference

| Constant (`src/config.rs`) | Used by | Value |
|---|---|---|
| `RP_ID` | derive + enrolment | `bitwarden-alternative.kevops` |
| `SALT_LABEL` | derive | `kevops-vault-encryption-salt-xyz` (hashed to 32 bytes by the extension) |
| `USER_ID` | enrolment | `b"kevops-vault-user"` |
| `CREDENTIAL_NAME_PREFIX` | naming | `kevops-feitan-ufa-passwordless-wrapper` |

## 6. Stream discipline (why stdout is exactly 64 chars)

`src/main.rs::print_vault_key` writes the key with `print!` and an explicit stdout
flush; **nothing else** reaches stdout — not the "tap the sensor" prompt, not the
confirmation. `tests/derive_flow.rs` pins this: a failing device yields **0 bytes
on stdout** and the failure message on stderr. This is what `Command::output()`
and shell pipelines depend on.
