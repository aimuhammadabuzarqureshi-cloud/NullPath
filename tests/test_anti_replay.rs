use decoypath::AntiReplayStore;

#[test]
fn test_anti_replay_fresh_message() {
    let mut store = AntiReplayStore::new();
    assert!(store.check_and_insert(0, b"msg_1"));
    assert!(store.check_and_insert(1, b"msg_2"));
    assert_eq!(store.len(), 2);
}

#[test]
fn test_anti_replay_duplicate_rejection() {
    let mut store = AntiReplayStore::new();
    assert!(store.check_and_insert(0, b"msg_1"));

    // Exact duplicate (seq=0, msg_1) must be rejected
    assert!(!store.check_and_insert(0, b"msg_1"));
    assert_eq!(store.len(), 1);
}

#[test]
fn test_anti_replay_capacity_eviction() {
    let mut store = AntiReplayStore::with_capacity_and_window(5, 300);

    for i in 0..5 {
        let msg_id = format!("msg_{}", i);
        assert!(store.check_and_insert(i, msg_id.as_bytes()));
    }
    assert_eq!(store.len(), 5);

    // 6th insertion triggers eviction of oldest entry
    assert!(store.check_and_insert(5, b"msg_5"));
    assert_eq!(store.len(), 5);
}
