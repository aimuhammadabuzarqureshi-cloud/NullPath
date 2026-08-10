use decoypath::{
    generate_identity_keypair, InitiatorState, RawDhSecret, ResponderState, RootKey,
};
use zeroize::Zeroize;

#[test]
fn test_happy_path_handshake() {
    let (initiator_priv, initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    // 1. Initiator initiates
    let (initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    // 2. Responder responds
    let (resp_payload, responder_root_key) = ResponderState::respond(
        &responder_priv,
        Some(&initiator_pub),
        &init_payload,
    )
    .unwrap();

    // 3. Initiator finalizes
    let initiator_root_key = initiator_state.finalize(&resp_payload).unwrap();

    // Both parties arrive at identical RootKey
    assert_eq!(initiator_root_key, responder_root_key);
}

#[test]
fn test_wrong_peer_identity_at_responder() {
    let (initiator_priv, _initiator_pub) = generate_identity_keypair();
    let (_wrong_priv, wrong_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    let (initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    // Responder expects wrong_pub instead of real initiator_pub
    let res = ResponderState::respond(&responder_priv, Some(&wrong_pub), &init_payload);
    assert!(res.is_err());
    drop(initiator_state);
}

#[test]
fn test_wrong_peer_identity_at_initiator() {
    let (initiator_priv, _initiator_pub) = generate_identity_keypair();
    let (_wrong_priv, wrong_pub) = generate_identity_keypair();
    let (responder_priv, _responder_pub) = generate_identity_keypair();

    // Initiator initiates expecting wrong_pub as responder
    let (initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, wrong_pub);

    // Responder attempts to respond using real responder_priv
    let res = ResponderState::respond(&responder_priv, None, &init_payload);
    assert!(res.is_err());
    drop(initiator_state);
}

#[test]
fn test_tampered_initiation_signature() {
    let (initiator_priv, initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    let (_state, mut init_payload) = InitiatorState::initiate(initiator_priv, responder_pub);

    // Corrupt signature
    init_payload.signature = ed25519_dalek::Signature::from_bytes(&[0xFF; 64]);

    let res = ResponderState::respond(&responder_priv, Some(&initiator_pub), &init_payload);
    assert!(res.is_err());
}

#[test]
fn test_tampered_initiation_nonce() {
    let (initiator_priv, initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    let (_state, mut init_payload) = InitiatorState::initiate(initiator_priv, responder_pub);

    // Corrupt nonce
    init_payload.nonce[0] ^= 0xFF;

    let res = ResponderState::respond(&responder_priv, Some(&initiator_pub), &init_payload);
    assert!(res.is_err());
}

#[test]
fn test_tampered_response_signature() {
    let (initiator_priv, initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    let (initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    let (mut resp_payload, _responder_key) =
        ResponderState::respond(&responder_priv, Some(&initiator_pub), &init_payload).unwrap();

    // Corrupt signature
    resp_payload.signature = ed25519_dalek::Signature::from_bytes(&[0xEE; 64]);

    let res = initiator_state.finalize(&resp_payload);
    assert!(res.is_err());
}

#[test]
fn test_key_isolation() {
    let (initiator_priv1, initiator_pub1) = generate_identity_keypair();
    let (responder_priv1, responder_pub1) = generate_identity_keypair();

    let (state1, init1) = InitiatorState::initiate(initiator_priv1, responder_pub1);
    let (resp1, responder_key1) = ResponderState::respond(&responder_priv1, Some(&initiator_pub1), &init1).unwrap();
    let initiator_key1 = state1.finalize(&resp1).unwrap();

    let (initiator_priv2, initiator_pub2) = generate_identity_keypair();
    let (responder_priv2, responder_pub2) = generate_identity_keypair();

    let (state2, init2) = InitiatorState::initiate(initiator_priv2, responder_pub2);
    let (resp2, responder_key2) = ResponderState::respond(&responder_priv2, Some(&initiator_pub2), &init2).unwrap();
    let initiator_key2 = state2.finalize(&resp2).unwrap();

    assert_eq!(initiator_key1, responder_key1);
    assert_eq!(initiator_key2, responder_key2);
    assert_ne!(initiator_key1, initiator_key2);
}

#[test]
fn test_zeroization_utility() {
    let mut key_buffer = [0x5A; 32];
    let root_key = RootKey(key_buffer);
    assert_eq!(root_key.0, [0x5A; 32]);

    key_buffer.zeroize();
    assert_eq!(key_buffer, [0u8; 32]);

    let mut raw_dh = RawDhSecret([0xBB; 32]);
    raw_dh.zeroize();
    assert_eq!(raw_dh.0, [0u8; 32]);

    let (mut priv_key, _pub_key) = generate_identity_keypair();
    priv_key.zeroize();
    assert_eq!(priv_key.0.to_bytes(), [0u8; 32]);
}
