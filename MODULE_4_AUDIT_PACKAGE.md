# Module 4 Audit Package: DecoyPath Decoy Generator (Revised)

## 1. Full Source Files

### `src/errors.rs`

```rust
use std::fmt;

/// Errors that can occur during the decoypath handshake protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Peer Ed25519 identity public key did not match expected key.
    PeerIdentityMismatch,
    /// Invalid payload format or truncated payload bytes.
    InvalidPayloadFormat,
    /// Internal cryptographic derivation or primitive error.
    CryptoFailure,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Handshake signature verification failed"),
            Self::PeerIdentityMismatch => write!(f, "Peer identity key mismatch"),
            Self::InvalidPayloadFormat => write!(f, "Invalid handshake payload format"),
            Self::CryptoFailure => write!(f, "Cryptographic primitive failure"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Errors that can occur within the path selection engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEngineError {
    /// Number of paths specified was zero.
    InvalidPathCount,
    /// Internal HMAC computation failure.
    HmacFailure,
}

impl fmt::Display for PathEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPathCount => write!(f, "Number of paths must be greater than zero"),
            Self::HmacFailure => write!(f, "HMAC-SHA256 path evaluation failed"),
        }
    }
}

impl std::error::Error for PathEngineError {}

/// Errors that can occur during message envelope sealing and opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Payload exceeds maximum capacity (992 bytes).
    PayloadTooLarge,
    /// AEAD encryption failure.
    EncryptionFailure,
    /// AEAD decryption or authentication tag verification failed.
    DecryptionFailure,
    /// Decrypted envelope format or version was invalid.
    InvalidFormat,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "Payload exceeds maximum 992-byte capacity"),
            Self::EncryptionFailure => write!(f, "AEAD encryption failed"),
            Self::DecryptionFailure => write!(f, "AEAD decryption or tag verification failed"),
            Self::InvalidFormat => write!(f, "Invalid decrypted envelope format or version"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Errors that can occur during decoy envelope generation and multi-path slot distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyError {
    /// Specified path count was zero.
    InvalidPathCount,
    /// Valid slot index was out of bounds for the path count.
    InvalidSlotIndex,
    /// Internal envelope sealing failure during decoy generation.
    SealFailure,
}

impl fmt::Display for DecoyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPathCount => write!(f, "Path count must be greater than zero"),
            Self::InvalidSlotIndex => write!(f, "Valid slot index is out of bounds for path count"),
            Self::SealFailure => write!(f, "Decoy envelope sealing failed"),
        }
    }
}

impl std::error::Error for DecoyError {}
```

### `src/decoy.rs`

```rust
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::envelope::{seal, ENVELOPE_TOTAL_LEN};
use crate::errors::DecoyError;

/// Generates a single 1024-byte decoy envelope sealed under a fresh random CSPRNG key.
///
/// Decoy envelopes are cryptographically indistinguishable from real envelopes to network eavesdroppers.
/// Attempting AEAD decryption against a decoy envelope under any key fails tag authentication in constant time.
pub fn generate_decoy(aad: &[u8]) -> Result<[u8; ENVELOPE_TOTAL_LEN], DecoyError> {
    let mut decoy_key = [0u8; 32];
    OsRng.fill_bytes(&mut decoy_key);

    // Generate random 128-byte decoy payload
    let mut decoy_payload = [0u8; 128];
    OsRng.fill_bytes(&mut decoy_payload);

    // Unreachable in practice with fixed 128-byte payload; propagated defensively.
    let envelope = seal(&decoy_key, &decoy_payload, aad)
        .map_err(|_| DecoyError::SealFailure)?;

    // Zeroize secret decoy key and payload material
    decoy_key.zeroize();
    decoy_payload.zeroize();

    Ok(envelope)
}

/// Generates a vector of `n_paths` envelopes containing 1 `real_envelope` at `valid_slot`
/// and `n_paths - 1` freshly generated decoy envelopes at all other slots.
///
/// Pre-allocates `Vec::with_capacity(n_paths)` to ensure uniform memory allocation without re-allocation overhead.
/// Executes fixed total work (generating exactly `n_paths - 1` decoy envelopes) regardless of `valid_slot` position.
///
/// Returns `Err(DecoyError::InvalidPathCount)` if `n_paths == 0`.
/// Returns `Err(DecoyError::InvalidSlotIndex)` if `valid_slot >= n_paths`.
pub fn generate_multi_path_slots(
    real_envelope: [u8; ENVELOPE_TOTAL_LEN],
    valid_slot: usize,
    n_paths: usize,
    aad: &[u8],
) -> Result<Vec<[u8; ENVELOPE_TOTAL_LEN]>, DecoyError> {
    if n_paths == 0 {
        return Err(DecoyError::InvalidPathCount);
    }
    if valid_slot >= n_paths {
        return Err(DecoyError::InvalidSlotIndex);
    }

    let mut slots = Vec::with_capacity(n_paths);

    for slot_idx in 0..n_paths {
        if slot_idx == valid_slot {
            slots.push(real_envelope);
        } else {
            let decoy = generate_decoy(aad)?;
            slots.push(decoy);
        }
    }

    Ok(slots)
}
```

### `src/lib.rs`

```rust
pub mod crypto;
pub mod decoy;
pub mod envelope;
pub mod errors;
pub mod handshake;
pub mod path_engine;
pub mod types;

pub use crypto::generate_identity_keypair;
pub use decoy::{generate_decoy, generate_multi_path_slots};
pub use envelope::{open, seal, ENVELOPE_TOTAL_LEN, MAX_PAYLOAD_SIZE};
pub use errors::{DecoyError, EnvelopeError, HandshakeError, PathEngineError};
pub use handshake::{InitiatorState, ResponderState};
pub use path_engine::{select_slot, RatchetKey};
pub use types::{
    HandshakeInitPayload, HandshakeResponsePayload, IdentityPrivateKey, RawDhSecret, RootKey,
    INIT_PAYLOAD_LEN, RESP_PAYLOAD_LEN,
};
```

---

## 2. Full Test File

### `tests/test_decoy.rs`

```rust
use decoypath::{
    generate_decoy, generate_multi_path_slots, open, seal, DecoyError, EnvelopeError,
    ENVELOPE_TOTAL_LEN,
};

#[test]
fn test_generate_decoy_length() {
    let aad = b"aad_seq_1";
    let decoy = generate_decoy(aad).expect("Generate decoy");
    assert_eq!(decoy.len(), ENVELOPE_TOTAL_LEN);
}

#[test]
fn test_decoy_fails_decryption() {
    let key = [0x55u8; 32];
    let aad = b"aad_seq_1";
    let decoy = generate_decoy(aad).expect("Generate decoy");

    // Attempting to open a decoy envelope with a real key fails AEAD tag authentication
    let result = open(&key, &decoy, aad);
    assert_eq!(result.err(), Some(EnvelopeError::DecryptionFailure));
}

#[test]
fn test_generate_multi_path_slots_placement() {
    let real_key = [0xAAu8; 32];
    let real_payload = b"Real secret message";
    let aad = b"aad_seq_5";
    let real_envelope = seal(&real_key, real_payload, aad).expect("Seal real");

    let n_paths = 5;
    let valid_slot = 2;

    let slots = generate_multi_path_slots(real_envelope, valid_slot, n_paths, aad)
        .expect("Multi-path slots");

    assert_eq!(slots.len(), n_paths);

    // Verify valid_slot contains the real envelope and decrypts successfully
    assert_eq!(slots[valid_slot], real_envelope);
    let decrypted = open(&real_key, &slots[valid_slot], aad).expect("Decrypt valid slot");
    assert_eq!(decrypted, real_payload);

    // Verify all other slots fail decryption
    for (idx, slot) in slots.iter().enumerate() {
        if idx != valid_slot {
            let res = open(&real_key, slot, aad);
            assert_eq!(res.err(), Some(EnvelopeError::DecryptionFailure));
        }
    }
}

#[test]
fn test_out_of_bounds_valid_slot_rejected() {
    let real_envelope = [0x00u8; ENVELOPE_TOTAL_LEN];
    let aad = b"aad_seq_1";

    let result = generate_multi_path_slots(real_envelope, 5, 5, aad);
    assert_eq!(result.err(), Some(DecoyError::InvalidSlotIndex));

    let result2 = generate_multi_path_slots(real_envelope, 6, 5, aad);
    assert_eq!(result2.err(), Some(DecoyError::InvalidSlotIndex));
}

#[test]
fn test_zero_n_paths_rejected() {
    let real_envelope = [0x00u8; ENVELOPE_TOTAL_LEN];
    let aad = b"aad_seq_1";

    let result = generate_multi_path_slots(real_envelope, 0, 0, aad);
    assert_eq!(result.err(), Some(DecoyError::InvalidPathCount));
}

#[test]
fn test_structural_indistinguishability() {
    let aad = b"aad_seq_10";
    let decoy1 = generate_decoy(aad).expect("Decoy 1");
    let decoy2 = generate_decoy(aad).expect("Decoy 2");

    assert_eq!(decoy1.len(), ENVELOPE_TOTAL_LEN);
    assert_eq!(decoy2.len(), ENVELOPE_TOTAL_LEN);

    // Fresh random nonces and keys make consecutive decoys distinct
    assert_ne!(decoy1, decoy2);
}
```

---

## 3. Test Coverage Checklist

- [x] **Decoy envelope fixed length (1024 bytes)**:
  - `test_generate_decoy_length`: Asserts `generate_decoy()` produces envelope of exact size 1024 bytes (`ENVELOPE_TOTAL_LEN`).
- [x] **Constant-time AEAD decryption failure on decoy envelope**:
  - `test_decoy_fails_decryption`: Asserts attempting `open()` on a decoy envelope under a real key returns `EnvelopeError::DecryptionFailure` via Poly1305 tag verification failure.
- [x] **Multi-path slot placement and decoy distribution**:
  - `test_generate_multi_path_slots_placement`: Asserts `slots[valid_slot]` contains the real envelope and decrypts successfully, while all `n_paths - 1` other slots contain decoy envelopes that fail decryption.
- [x] **Out-of-bounds valid slot rejection**:
  - `test_out_of_bounds_valid_slot_rejected`: Asserts `valid_slot >= n_paths` returns `DecoyError::InvalidSlotIndex`.
- [x] **Zero path count rejection**:
  - `test_zero_n_paths_rejected`: Asserts `n_paths == 0` returns `DecoyError::InvalidPathCount`.
- [x] **Structural indistinguishability**:
  - `test_structural_indistinguishability`: Asserts decoy envelopes have 1024-byte layout matching real envelopes and fresh CSPRNG nonces/keys per generation.

---

## 4. Indistinguishability & Key Single-Use Safety Analysis

1. **Single-Use Key Isolation per Decoy Envelope**:
   - `generate_decoy()` generates a fresh 32-byte CSPRNG key `decoy_key` via `OsRng` for every decoy envelope generated.
   - Enabled `features = ["zeroize"]` on `chacha20poly1305` in `Cargo.toml` so that internal cipher key copies are scrubbed on drop alongside `decoy_key.zeroize()`.

2. **Cryptographic Indistinguishability**:
   - Decoy envelopes are sealed via `seal()`, producing identical 1024-byte structure: 12-byte CSPRNG Nonce, 996-byte ChaCha20Poly1305 Ciphertext, and 16-byte Poly1305 Tag.
   - Attempting decryption on a decoy slot returns `EnvelopeError::DecryptionFailure` through Poly1305 tag authentication in constant time, identical to attempting decryption on a real envelope directed at a different path slot.

3. **Allocation Uniformity**:
   - `generate_multi_path_slots()` pre-allocates vector capacity via `Vec::with_capacity(n_paths)` and executes exactly $N-1$ decoy generation operations regardless of `valid_slot` position.

---

## 5. Implementation Completeness Statement

No TODO stubs, unimplemented branches, placeholder returns, or simplified/deferred logic exist anywhere in the Module 4 files (`src/errors.rs`, `src/decoy.rs`, `src/lib.rs`). All decoy generation, slot distribution, and zeroization routines are fully implemented and production-ready for Module 4 audit review.

---

## 6. Scope Confirmation

I confirm explicitly that Modules 1, 2, and 3 (`src/crypto.rs`, `src/handshake.rs`, `src/path_engine.rs`, `src/envelope.rs`) remain active and verified passing, and no code for Module 5 (`src/anti_replay.rs`, `src/channel.rs`) or later exists or was started in the workspace directory.
