use decoypath::{select_slot, PathEngineError, RatchetKey};
use zeroize::Zeroize;

#[test]
fn test_slot_selection_determinism() {
    let key = [0x42u8; 32];
    let message_id = b"msg_1001";
    let n_paths = 10;

    let slot1 = select_slot(&key, message_id, n_paths).expect("Slot 1 selection");
    let slot2 = select_slot(&key, message_id, n_paths).expect("Slot 2 selection");

    assert_eq!(slot1, slot2);
    assert!(slot1 < n_paths);
}

#[test]
fn test_slot_selection_bounds() {
    let key = [0x1Du8; 32];
    let n_paths = 7;

    for i in 0..100 {
        let msg_id = format!("message_{}", i);
        let slot = select_slot(&key, msg_id.as_bytes(), n_paths).expect("Slot selection");
        assert!(slot < n_paths);
    }
}

#[test]
fn test_zero_paths_returns_error() {
    let key = [0x55u8; 32];
    let message_id = b"msg_test";

    let result = select_slot(&key, message_id, 0);
    assert_eq!(result.err(), Some(PathEngineError::InvalidPathCount));
}

#[test]
fn test_ratchet_key_forward_chain() {
    let k0 = RatchetKey::new([0x01u8; 32]);
    let k1 = k0.derive_next();
    let k2 = k1.derive_next();

    assert!(!k0.ct_eq(&k1));
    assert!(!k1.ct_eq(&k2));
    assert!(!k0.ct_eq(&k2));

    // Deterministic progression
    let k1_again = k0.derive_next();
    assert!(k1.ct_eq(&k1_again));
}

#[test]
fn test_ratchet_key_duplicate_for_target_use() {
    let k0 = RatchetKey::new([0x77u8; 32]);
    let target_key = k0.duplicate_for_target_use();

    assert!(k0.ct_eq(&target_key));
    assert_eq!(target_key.0, [0x77u8; 32]);
}

#[test]
fn test_ratchet_key_zeroization() {
    let mut key = RatchetKey::new([0xFFu8; 32]);
    assert_eq!(key.0, [0xFFu8; 32]);

    key.zeroize();
    assert_eq!(key.0, [0u8; 32]);
}

#[test]
fn test_slot_distribution_uniformity() {
    let key = [0x99u8; 32];
    let n_paths = 8;
    let mut counts = vec![0; n_paths];

    for i in 0..1000 {
        let msg_id = format!("msg_dist_{}", i);
        let slot = select_slot(&key, msg_id.as_bytes(), n_paths).expect("Slot");
        counts[slot] += 1;
    }

    // Ensure every slot was selected at least once
    for (slot_idx, count) in counts.iter().enumerate() {
        assert!(*count > 0, "Slot {} was never selected", slot_idx);
    }
}

#[test]
fn test_ratchet_key_domain_separation() {
    use sha2::{Digest, Sha256};

    let key_bytes = [0xAAu8; 32];
    let k0 = RatchetKey::new(key_bytes);
    let next = k0.derive_next();

    // Bare SHA256 without domain separation tag produces a different output!
    let mut bare_hasher = Sha256::new();
    bare_hasher.update(&key_bytes);
    let bare_digest: [u8; 32] = bare_hasher.finalize().into();

    assert_ne!(next.0, bare_digest);
}
