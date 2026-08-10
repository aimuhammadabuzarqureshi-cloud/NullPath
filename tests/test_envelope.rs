use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use decoypath::{open, seal, EnvelopeError, ENVELOPE_TOTAL_LEN, MAX_PAYLOAD_SIZE};

#[test]
fn test_happy_path_roundtrip() {
    let key = [0x77u8; 32];
    let payload = b"Hello, DecoyPath Secure Channel!";
    let aad = b"aad_seq_1";

    let envelope = seal(&key, payload, aad).expect("Seal envelope");
    assert_eq!(envelope.len(), ENVELOPE_TOTAL_LEN);

    let decrypted = open(&key, &envelope, aad).expect("Open envelope");
    assert_eq!(decrypted, payload);
}

#[test]
fn test_envelope_fixed_length() {
    let key = [0x12u8; 32];
    let payload = vec![0xABu8; 500];
    let aad = b"aad_test";

    let envelope = seal(&key, &payload, aad).expect("Seal");
    assert_eq!(envelope.len(), ENVELOPE_TOTAL_LEN);
}

#[test]
fn test_payload_too_large_rejected() {
    let key = [0x33u8; 32];
    let oversized_payload = vec![0x66u8; MAX_PAYLOAD_SIZE + 1];
    let aad = b"aad_test";

    let result = seal(&key, &oversized_payload, aad);
    assert_eq!(result.err(), Some(EnvelopeError::PayloadTooLarge));
}

#[test]
fn test_tampered_ciphertext_rejected() {
    let key = [0x44u8; 32];
    let payload = b"Secret Message";
    let aad = b"aad_test";

    let mut envelope = seal(&key, payload, aad).expect("Seal");

    // Corrupt ciphertext byte
    envelope[50] ^= 0xFF;

    let result = open(&key, &envelope, aad);
    assert_eq!(result.err(), Some(EnvelopeError::DecryptionFailure));
}

#[test]
fn test_tampered_aad_rejected() {
    let key = [0x55u8; 32];
    let payload = b"Secret Message";
    let valid_aad = b"aad_seq_10";
    let forged_aad = b"aad_seq_11";

    let envelope = seal(&key, payload, valid_aad).expect("Seal");

    let result = open(&key, &envelope, forged_aad);
    assert_eq!(result.err(), Some(EnvelopeError::DecryptionFailure));
}

#[test]
fn test_tampered_nonce_rejected() {
    let key = [0x88u8; 32];
    let payload = b"Secret Message";
    let aad = b"aad_test";

    let mut envelope = seal(&key, payload, aad).expect("Seal");

    // Corrupt nonce byte
    envelope[0] ^= 0xAA;

    let result = open(&key, &envelope, aad);
    assert_eq!(result.err(), Some(EnvelopeError::DecryptionFailure));
}

#[test]
fn test_csprng_padding_randomization() {
    let key = [0x99u8; 32];
    let payload = b"Short payload";
    let aad = b"aad_test";

    let env1 = seal(&key, payload, aad).expect("Seal 1");
    let env2 = seal(&key, payload, aad).expect("Seal 2");

    // Nonces and random padding cause two envelopes to differ completely
    assert_ne!(env1, env2);
}

#[test]
fn test_invalid_version_byte_rejected() {
    let key = [0xAAu8; 32];
    let aad = b"aad_test";
    let nonce_bytes = [0x11u8; 12];

    // Build validly authenticated AEAD ciphertext with invalid version 0x02
    let mut plaintext = [0u8; 996];
    plaintext[0] = 0x02; // Invalid version byte!
    plaintext[1] = 0x00;
    plaintext[2..4].copy_from_slice(&(10u16).to_be_bytes());

    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut plaintext)
        .expect("Encrypt valid AEAD tag");

    let mut envelope = [0u8; ENVELOPE_TOTAL_LEN];
    envelope[0..12].copy_from_slice(&nonce_bytes);
    envelope[12..1008].copy_from_slice(&plaintext);
    envelope[1008..1024].copy_from_slice(tag.as_slice());

    let result = open(&key, &envelope, aad);
    assert_eq!(result.err(), Some(EnvelopeError::InvalidFormat));
}

#[test]
fn test_invalid_payload_len_rejected() {
    let key = [0xBBu8; 32];
    let aad = b"aad_test";
    let nonce_bytes = [0x22u8; 12];

    // Build validly authenticated AEAD ciphertext with invalid payload length 0xFFFF (65535 > 992)
    let mut plaintext = [0u8; 996];
    plaintext[0] = 0x01; // Valid version
    plaintext[1] = 0x00;
    plaintext[2..4].copy_from_slice(&(0xFFFFu16).to_be_bytes()); // Oversized payload len!

    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut plaintext)
        .expect("Encrypt valid AEAD tag");

    let mut envelope = [0u8; ENVELOPE_TOTAL_LEN];
    envelope[0..12].copy_from_slice(&nonce_bytes);
    envelope[12..1008].copy_from_slice(&plaintext);
    envelope[1008..1024].copy_from_slice(tag.as_slice());

    let result = open(&key, &envelope, aad);
    assert_eq!(result.err(), Some(EnvelopeError::InvalidFormat));
}
