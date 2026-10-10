# 🔐 KevOps Feitian UFA Wrapper

> 🧰 Derive a deterministic **256-bit AES vault key** from a **Feitian BioPass FIDO2** fingerprint
> authenticator using the CTAP2 **hmac-secret** extension — no vault secret is ever stored on disk.

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Edition](https://img.shields.io/badge/edition-2024-blue.svg)](https://doc.rust-lang.org/edition-guide/)
[![Crate](https://img.shields.io/badge/ctap--hid--fido2-3.6.0-green.svg)](https://crates.io/crates/ctap-hid-fido2)

---

## 🧭 Overview

The wrapper asks a Feitian BioPass USB authenticator to compute
`HMAC-SHA-256(CredRandom, salt)`, where `CredRandom` is a secret that **never leaves the secure
element**. The 32-byte output is then hashed once more with SHA-256 to produce a fixed-length key
suitable for AES-256.

```
┌──────────────────┐   CTAP2 / USB HID    ┌───────────────────────┐
│  kevops wrapper  │ ───────────────────► │  Feitian BioPass      │
│  (Rust binary)   │ ◄─────────────────── │  (secure element)     │
└──────────────────┘   hmac-secret output └───────────────────────┘
        │                                            │
        │  salt (32B, SHA-256 of label)              │  👆 fingerprint = user verification
        ▼                                            ▼
   SHA-256(output) ──────────►  32-byte AES-256 vault key
```

| 🔑 Property | Value |
|---|---|
| 🚪 Relying Party ID | `bitwarden-alternative.kevops` |
| 🧂 Salt label | `kevops-vault-encryption-salt-xyz` |
| 🔌 Device | Feitian BioPass `vid 0x096e / pid 0x085d` (fallback All-in-Pass `0x0866`) |
| 🛡️ Verification | On-device UV (`uv = Some(true)`) — the fingerprint |
| 📏 Key size | 32 bytes (AES-256), printed as lowercase hex |

---

## ✅ Prerequisites

| 📦 Requirement | Notes |
|---|---|
| 🦀 Rust **1.85+** | The crate uses `edition = "2024"` |
| 🔧 Build deps | `hidapi` needs `libudev` + `pkg-config` |
| 🔌 Hardware | Feitian BioPass (USB) with **at least one fingerprint enrolled** |
| 🔐 udev access | Non-root users need a hidraw rule (see below) |

```bash
# 🐧 Debian / Ubuntu build dependencies
sudo apt-get install -y pkg-config libudev-dev
```

### 🦶 udev rule (required on Linux)

Without this the process fails with `Failed to open device.`:

```bash
sudo tee /etc/udev/rules.d/70-feitian-biopass.rules > /dev/null <<'EOF'
# Feitian BioPass / All-in-Pass FIDO2
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="096e", ATTRS{idProduct}=="085d", MODE="0660", GROUP="plugdev", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="096e", ATTRS{idProduct}=="0866", MODE="0660", GROUP="plugdev", TAG+="uaccess"
EOF

sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev "$USER"   # re-login for group change to apply
```

---

## 🚀 Quickstart

```bash
git clone https://github.com/keverall/kevops-feitian-ufa-wrapper.git
cd kevops-feitian-ufa-wrapper

cargo check            # 🧪 fast feedback
cargo build --release  # 📦 optimized artifact

cargo run --release    # 👆 prompts for the fingerprint
```

Expected output:

```
⚡ Please tap the Feitian BioPass fingerprint sensor...
🔓 Fingerprint verified! 256-bit Vault key derived: <64 hex chars>
```

> ⚠️ **Keep `Cargo.lock` committed** — this is a binary crate, so the lockfile is what makes builds
> reproducible across dev, CI, and release.

---

## 🏗️ DevOps Principles & Best Practices

### 🎯 Core principles applied

| | Principle | How this repo honours it |
|---|---|---|
| 🔁 | **Automate everything** | Every step is a single `cargo` command; no manual key handling or copy-paste steps |
| 🏗️ | **Everything as code** | Build, lint, and release config live in the repo, versioned with the source |
| 📦 | **Immutable, reproducible artifacts** | `Cargo.lock` committed; `--release` builds are treated as immutable |
| 🧪 | **Shift-left testing** | `cargo check` for fast feedback, `cargo clippy` and `cargo fmt --check` as gates |
| 🔒 | **Security by default / least privilege** | Runs unprivileged; scoped udev rule only for the Feitian VID/PID |
| 🚫 | **Zero secrets at rest** | No vault key, PIN, or credential material is persisted anywhere on disk |
| 🔗 | **Supply-chain integrity** | Pinned dependency versions, committed lockfile, `cargo audit` in CI |
| 📊 | **Observability** | Structured CTAP/HID tracing via `Cfg::init()` + keep-alive user prompts |
| 🧯 | **Fail fast, fail loud** | Explicit errors for missing device / missing hmac-secret output |
| ♻️ | **Idempotent & stateless** | The binary holds no state; re-running yields the same key for the same device+salt |
| 📝 | **Docs as code** | This README changes in the same PR as the behaviour it documents |

### 🧪 Recommended quality gates

```bash
cargo fmt --check   # 🎨 formatting is not a matter of taste
cargo clippy --all-targets -- -D warnings   # 🧹 lint gate
cargo test          # 🔬 unit + integration tests
cargo audit         # 🔗 dependency vulnerability scan
cargo build --release   # 📦 release artifact
```

### 🔁 Recommended CI pipeline

```yaml
# .github/workflows/ci.yml (suggested starting point)
name: ci
on: [push, pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: "rustfmt, clippy" }
      - run: sudo apt-get install -y pkg-config libudev-dev   # 🔧 hidapi
      - run: cargo fmt --check                                # 🎨
      - run: cargo clippy --all-targets -- -D warnings        # 🧹
      - run: cargo build --release                            # 📦
      - uses: rustsec/audit-check@v2                          # 🔗 supply chain
        with: { token: "${{ secrets.GITHUB_TOKEN }}" }
```

> 🤖 Hardware-in-the-loop (real BioPass) cannot run on hosted runners — keep the device-dependent
> path behind a self-hosted runner or a manual smoke-test job.

### 🔖 Release & versioning

- 🏷️ **Semantic versioning** driven by `Cargo.toml`.
- 🌿 **Trunk-based**: short-lived branches, PR required, green CI before merge.
- 🧾 **Tagged releases** build once and publish the artifact — never rebuild per environment.
- 🔐 **Supply chain**: review `cargo audit` output before every release; bump `ctap-hid-fido2`
  deliberately (its API changed between minor versions — see Troubleshooting).

---

## 🔐 Security Model

| 🛡️ Control | Detail |
|---|---|
| 🔏 Key custody | `CredRandom` never leaves the secure element; only its HMAC output is returned |
| 👆 User verification | `uv = Some(true)` forces the fingerprint — the key cannot be derived from a stale token |
| 🧂 Domain separation | A distinct 32-byte salt per vault database; changing the salt yields a different key |
| 🚫 No persistence | Nothing is written to disk; the key goes to stdout for the caller to consume |
| 🔑 No fallback secrets | There is no password or recovery file that bypasses the hardware |

> ⚠️ **stdout is not a secret channel.** When wiring this into a vault, capture stdout directly
> (pipe or `Command::output()`), avoid shell history and shared terminals, and never redirect the
> key to a file or a log.

---

## 📊 Observability

```rust
let mut cfg = Cfg::init();
cfg.enable_log = true;                // 🕵️ verbose CTAP/HID hex tracing
cfg.keep_alive_msg_to_stderr = true;  // 📣 keep prompts off stdout
```

- 🕵️ `enable_log` — full CTAP frame tracing while debugging device issues.
- 📣 `keep_alive_msg` — user-facing "touch the sensor" prompt; route to **stderr** when stdout is
  consumed as the key channel (recommended for automation).

---

## 🧯 Troubleshooting

| 🚨 Symptom | ✅ Fix |
|---|---|
| `Failed to open device.` | 🔌 Check `lsusb` for `096e:085d`; install the udev rule; re-login for `plugdev`; confirm the device is not claimed by another process (`pcscd`, browser WebAuthn) |
| `unresolved import fidokeyhid` / `no method get_hmac_secret` | 📦 Those APIs do not exist in `ctap-hid-fido2` 3.6.0 — use `GetAssertionArgsBuilder` + `AssertionExtension::HmacSecret` |
| Salt rejected / panic on unwrap | 🧂 The salt must be exactly **32 bytes**; use `create_hmac_secret_from_string` |
| `no assertion returned` | 🪪 No credential registered for the RP ID — enroll with `CredentialExtension::HmacSecret(Some(true))` first |
| No hmac-secret output, finger accepted | 🔑 Many authenticators require a `pinUvAuthToken`; supply a PIN via `.pin(...)` (note: this sets `uv = None`) |
| Permission denied opening hidraw | 🦶 Re-apply the udev rule and verify `groups` includes `plugdev` |
| Fingerprint never triggers | 👆 Ensure a fingerprint is enrolled and the device is not in U2F-only mode |

---

## 🗺️ Known Limitations & Roadmap

- 🪪 **Enrollment is out of scope** — the credential for the RP ID must already exist with
  hmac-secret enabled. Roadmap: a one-time `make_credential` enrollment subcommand.
- 🔑 **PIN fallback** not wired up; some authenticators require it for hmac-secret.
- 🧪 **No automated tests** yet — the crate's `get_assertion` flow needs a mock/simulator layer.
- 🧩 **Single device model** — only `096e:085d` / `096e:0866` are probed; consider `HidParam::get()`
  plus a first-match prompt for broader device support.

---

## 📚 References

- 📘 [CTAP 2.1 — HMAC Secret Extension (§12.5)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension)
- 📦 [ctap-hid-fido2 crate](https://crates.io/crates/ctap-hid-fido2)
- 🦀 [Rust Edition 2024](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)
- 🔐 [FIDO2 / WebAuthn spec](https://www.w3.org/TR/webauthn-3/)

---

<sub>🤖 Built with a DevOps-first mindset: reproducible builds, least privilege, zero secrets at rest.</sub>
