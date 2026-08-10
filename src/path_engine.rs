use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::PathEngineError;

type HmacSha256 = Hmac<Sha256>;

/// 256-bit symmetric ratchet key with automatic zeroization on drop.
/// Does NOT derive `Clone` or `Copy` to prevent untracked secret key duplication.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetKey(pub [u8; 32]);

impl RatchetKey {
    /// Constructs a new RatchetKey wrapper from raw 32 bytes.
    pub fn new(key_bytes: [u8; 32]) -> Self {
        Self(key_bytes)
    }

    /// Explicitly sanctioned key duplication for single-use decryption target key use.
    pub fn duplicate_for_target_use(&self) -> Self {
        Self(self.0)
    }

    /// Advances the forward-secret hash chain by one step:
    /// `next_key = SHA256(b"decoypath-v1-ratchet-advance:" || current_key)`.
    pub fn derive_next(&self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"decoypath-v1-ratchet-advance:");
        hasher.update(&self.0);
        let digest = hasher.finalize();
        let mut next_bytes = [0u8; 32];
        next_bytes.copy_from_slice(&digest);
        Self(next_bytes)
    }

    /// Constant-time key equality comparison to prevent timing side-channels.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[cfg(test)]
impl PartialEq for RatchetKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

#[cfg(test)]
impl Eq for RatchetKey {}

impl std::fmt::Debug for RatchetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RatchetKey([REDACTED])")
    }
}

/// Deterministically selects a path slot index in range `[0 .. n_paths)` using HMAC-SHA256.
///
/// Returns `Err(PathEngineError::InvalidPathCount)` if `n_paths == 0`.
pub fn select_slot(
    key: &[u8],
    message_id: &[u8],
    n_paths: usize,
) -> Result<usize, PathEngineError> {
    if n_paths == 0 {
        return Err(PathEngineError::InvalidPathCount);
    }

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| PathEngineError::HmacFailure)?;
    mac.update(message_id);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    let value_bytes: [u8; 8] = code_bytes[0..8]
        .try_into()
        .map_err(|_| PathEngineError::HmacFailure)?;
    let raw_val = u64::from_be_bytes(value_bytes);

    Ok((raw_val % (n_paths as u64)) as usize)
}
