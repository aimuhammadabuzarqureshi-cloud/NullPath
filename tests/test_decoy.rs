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
