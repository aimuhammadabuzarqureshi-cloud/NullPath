use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::errors::EnvelopeError;

/// Fixed total size of every decoypath envelope (1024 bytes).
pub const ENVELOPE_TOTAL_LEN: usize = 1024;

/// Maximum raw payload capacity per envelope (992 bytes).
pub const MAX_PAYLOAD_SIZE: usize = 992;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const CIPHERTEXT_LEN: usize = 996;
pub const PLAINTEXT_LEN: usize = 996;

/// Seals a plaintext payload into a fixed 1024-byte envelope using ChaCha20Poly1305 AEAD.
///
/// Plaintext structure (996 bytes):
/// - `[0]`: Version (`0x01`)
/// - `[1]`: Flags (`0x00`)
/// - `[2..4]`: 2-byte big-endian `payload_len`
/// - `[4 .. 4 + payload_len]`: raw payload bytes
/// - `[4 + payload_len .. 996]`: CSPRNG random padding bytes
///
/// # Key Reuse & Nonce Collision Safety
/// Callers **MUST** supply a unique, single-use key for every `seal()` invocation.
/// Reusing a key across multiple `seal()` calls with random 96-bit nonces creates a nonce-collision
/// risk under the birthday bound that can catastrophically break both confidentiality and authentication.
/// This module does not enforce single-use keys internally — see Module 5 (`channel.rs`) for the
/// ratchet mechanism that guarantees single-use key isolation per message.
pub fn seal(
    key: &[u8; 32],
    payload: &[u8],
    aad: &[u8],
) -> Result<[u8; ENVELOPE_TOTAL_LEN], EnvelopeError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(EnvelopeError::PayloadTooLarge);
    }

    let mut envelope = [0u8; ENVELOPE_TOTAL_LEN];

    // Generate random 12-byte CSPRNG Nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    envelope[0..NONCE_LEN].copy_from_slice(&nonce_bytes);

    // Build 996-byte plaintext buffer with version, payload_len, payload, and CSPRNG padding
    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext[0] = 0x01; // Version
    plaintext[1] = 0x00; // Reserved flags
    let len_bytes = (payload.len() as u16).to_be_bytes();
    plaintext[2..4].copy_from_slice(&len_bytes);

    plaintext[4..4 + payload.len()].copy_from_slice(payload);
    if 4 + payload.len() < PLAINTEXT_LEN {
        OsRng.fill_bytes(&mut plaintext[4 + payload.len()..PLAINTEXT_LEN]);
    }

    // ChaCha20Poly1305 AEAD Encryption
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut plaintext)
        .map_err(|_| EnvelopeError::EncryptionFailure)?;

    envelope[NONCE_LEN..NONCE_LEN + CIPHERTEXT_LEN].copy_from_slice(&plaintext);
    envelope[NONCE_LEN + CIPHERTEXT_LEN..ENVELOPE_TOTAL_LEN].copy_from_slice(tag.as_slice());

    // Zeroize intermediate plaintext buffer
    plaintext.zeroize();

    Ok(envelope)
}

/// Opens and authenticates a 1024-byte envelope, returning the decrypted payload.
pub fn open(
    key: &[u8; 32],
    envelope: &[u8; ENVELOPE_TOTAL_LEN],
    aad: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let nonce_bytes = &envelope[0..NONCE_LEN];
    let ciphertext_bytes = &envelope[NONCE_LEN..NONCE_LEN + CIPHERTEXT_LEN];
    let tag_bytes = &envelope[NONCE_LEN + CIPHERTEXT_LEN..ENVELOPE_TOTAL_LEN];

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let tag = Tag::from_slice(tag_bytes);

    let mut buffer = [0u8; PLAINTEXT_LEN];
    buffer.copy_from_slice(ciphertext_bytes);

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
        .map_err(|_| EnvelopeError::DecryptionFailure)?;

    if buffer[0] != 0x01 {
        buffer.zeroize();
        return Err(EnvelopeError::InvalidFormat);
    }

    let payload_len = u16::from_be_bytes(buffer[2..4].try_into().unwrap()) as usize;
    if payload_len > MAX_PAYLOAD_SIZE {
        buffer.zeroize();
        return Err(EnvelopeError::InvalidFormat);
    }

    let payload = buffer[4..4 + payload_len].to_vec();

    // Zeroize decrypted buffer before returning
    buffer.zeroize();

    Ok(payload)
}
