# REVIEW.md

Guidance for the automated Kilo reviewer on this repository.

`README.md` and `docs/architecture.md` are the policy documents for this crate —
read them first and treat them as the spec. Review the cumulative PR/MR diff
against its base branch, not only the latest commit. Be helpful, not pedantic:
frame everything as a suggestion the human can accept or reject.

This is a hardware-key CLI (Rust, `ctap-hid-fido2`): the derive path produces an
AES-256 vault key on stdout, and the enroll path manages discoverable
credentials on a Feitian BioPass. Bugs here can strand a vault key or destroy
credentials, so weight correctness and data-safety above style.

## What to focus on

### 1. Stream discipline (stdout is a key channel)

`src/main.rs::print_vault_key` must be the only writer to stdout on the derive
path: exactly 64 lowercase hex chars (32 bytes, `print!` + explicit flush, no
trailing newline beyond the hex). Every prompt, keep-alive, progress and error
message goes to stderr — including `Cfg::enable_keep_alive_msg` /
`keep_alive_msg_to_stderr` wiring in `src/device.rs::open_device`.

- Flag any `println!`, `print!`, `dbg!`, or library log default that can reach
  stdout in the derive path.
- Flag any change that makes stdout content conditional on a failure path (the
  contract asserts 0 bytes on stdout when device handling fails).

### 2. Key derivation correctness

`derive` must remain `HMAC-SHA-256(CredRandom, salt)` computed by the
authenticator's hmac-secret extension, then one SHA-256 over the 32-byte output
(`src/crypto.rs`). The salt must stay exactly 32 bytes
(`create_hmac_secret_from_string`), the RP ID stays
`bitwarden-alternative.kevops`, and `to_hex` output stays lowercase and
deterministic. Flag anything that changes the key derivation, salt handling,
domain separation, or the RP ID — that silently rotates every existing vault
key.

### 3. Enrolment ordering invariant

Credential replacement must keep the documented call order
`Create → Rename → Delete` and never delete the old credential before the new
one is confirmed and named. Deletion must target only credentials whose names
start with `CREDENTIAL_NAME_PREFIX`
(`kevops-feitan-ufa-passwordless-wrapper`), preserving unrelated credentials
registered under the same RP ID. Sequential naming (`wrapperNN`, zero-padded)
lives in `src/naming.rs`.

- Flag reordering, early delete, unfiltered delete, or any change that removes
  the `tests/common/mod.rs` `FakeDevice` ordering assertions.
- Replacement is non-transactional by nature: partial failure (created but not
  renamed, renamed but old not deleted) must be reported explicitly to the user
  on stderr. Do not let error messages imply the operation is atomic or that it
  rolled back.

### 4. PIN and user-verification handling

The PIN is a non-retrievable shared secret: never log, echo, or persist it, and
never send it anywhere but the `pinUvAuthToken` exchange.

- `--pin` authorization sets `uv = None` (pinUvAuth bypasses the fingerprint);
  fingerprint UV (`uv = Some(true)`) is the preferred default. User-facing
  messages must describe the authorization actually used — flag messages that
  claim "Fingerprint verified" after a PIN-based authorization.
- CTAP2 PIN status codes must surface as actionable `VaultError` messages
  (e.g. `0x31` invalid, `0x32` blocked → power-cycle, `0x34` auth-blocked →
  device reset required), never `unwrap()`/`expect()` panics or raw hex dumps.

### 5. Test and API surface

The suite is hardware-free and runs flows against the recording `FakeDevice`;
new flow behavior needs matching tests (ordering, naming, R/A prompt policy,
stdout contract). Public items keep `///` docs (`missing_docs` is a deny-by-
default lint here), and hardware-facing code stays behind the `VaultDevice`
trait so tests never touch the device.

## Severity calibration

**Critical** — anything that strands or exposes the vault key; changes the
derived key; deletes wrong or not-yet-replaced credentials; writes non-key
bytes to stdout; logs or persists the PIN.

**Warning** — broken ordering guarantees; unfiltered credential deletion;
misleading UV/verification messages; panics on device or CTAP2 paths; removed
or weakened tests; missing docs on new public API.

**Suggestion** — clearer error text, naming, structure, or test organization
that does not change behavior.

## What not to flag

- Formatting, import order, or clippy-clean style — `make ci`
  (`fmt-check`, `taplo`, `clippy -D warnings`) already gates those.
- Emoji, badge, or table-layout churn in `README.md` / `docs/architecture.md`
  unless it contradicts behavior.
- `Cargo.lock` version bumps (the lockfile is committed deliberately) unless a
  jumped dependency touches CTAP2/device APIs without a note in the description.
- Hardware-only behavior that the diff cannot prove (real assertion timing,
  sensor touch); say it is unverified and name the manual smoke test instead.
- Whether reviewers can reproduce the command surface — if a change alters
  `enroll` / `derive` flags or their exit codes, do check `src/cli.rs` and
  `src/error.rs` together.

## Verification expectations

Review from repository content and CI evidence. Expected green gates:
`make ci` (fmt + toml-lint + clippy `-D warnings` + tests + rustdoc) and
`cargo audit`. CI passing alone does not prove the invariant tests still assert
ordering, filtering, or the stdout contract — read the test diff too. If a
behavior change has no test, say what is unverified and give the exact command
the maintainer can run (`make test`, or a manual hardware smoke test for the
real device round trip).

## Comment and summary style

- Inline comments only on valid diff lines, with path, line, trigger, impact,
  and a minimal fix. Group cross-cutting instances in the summary.
- Deduplicate; do not repeat what CI or `cargo clippy` already enforces.
- Every finding must be specific to this repo's invariants above, not a generic
  checklist.
- If the PR is clean against the above, say so with a short summary of the
  evidence reviewed (`lgtm`).

## Sub-agent usage

This is a small, single-binary crate — default to reviewing directly.

- Use 0 sub-agents for docs, formatting, dependency-lockfile-only, or
  single-file changes.
- Use 1 sub-agent only when the diff touches one risky area (crypto/derivation,
  enrol ordering, credential deletion) and spans more than about 300 changed
  lines; have it re-check the invariant tests for that area.
- Do not use the full sub-agent tier — the diff surface here is too small to
  shard by domain.
- Sub-agents stay read-only, never post comments, and return findings with
  path, line, severity, rationale, and confidence. The main reviewer verifies
  every finding before posting.
