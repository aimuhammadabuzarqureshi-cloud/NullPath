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
