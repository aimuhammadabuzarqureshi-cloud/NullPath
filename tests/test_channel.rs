use decoypath::*;

fn setup_channel_pair(n_paths: usize) -> (SecureChannel, SecureChannel) {
    let (init_priv, init_pub) = generate_identity_keypair();
    let (resp_priv, resp_pub) = generate_identity_keypair();

    let (init_state, init_payload) = InitiatorState::initiate(init_priv, resp_pub);
    let (resp_payload, resp_root_key) =
        ResponderState::respond(&resp_priv, Some(&init_pub), &init_payload).unwrap();
    let init_root_key = init_state.finalize(&resp_payload).unwrap();

    let sender = SecureChannel::new(init_root_key, n_paths);
    let receiver = SecureChannel::new(resp_root_key, n_paths);

    (sender, receiver)
}

#[test]
fn test_channel_in_order_flow() {
    let (mut sender, mut receiver) = setup_channel_pair(4);

    let env0 = sender.send(b"Hello 0", b"msg_0").unwrap();
    let res0 = receiver.receive(&env0, 0, b"msg_0").unwrap();
    assert_eq!(res0, b"Hello 0");
    assert_eq!(receiver.last_seq(), Some(0));

    let env1 = sender.send(b"Hello 1", b"msg_1").unwrap();
    let res1 = receiver.receive(&env1, 1, b"msg_1").unwrap();
    assert_eq!(res1, b"Hello 1");
    assert_eq!(receiver.last_seq(), Some(1));
}

#[test]
fn test_channel_bootstrap_seq_zero() {
    let (mut sender, mut receiver) = setup_channel_pair(4);

    let env0 = sender.send(b"Bootstrap Payload", b"boot_msg").unwrap();
    let res0 = receiver.receive(&env0, 0, b"boot_msg").unwrap();
    assert_eq!(res0, b"Bootstrap Payload");
    assert_eq!(receiver.last_seq(), Some(0));
}

#[test]
fn test_channel_out_of_order_flow() {
    let (mut sender, mut receiver) = setup_channel_pair(4);

    let env0 = sender.send(b"Payload 0", b"msg_0").unwrap();
    let env1 = sender.send(b"Payload 1", b"msg_1").unwrap();
    let env2 = sender.send(b"Payload 2", b"msg_2").unwrap();

    let res0 = receiver.receive(&env0, 0, b"msg_0").unwrap();
    assert_eq!(res0, b"Payload 0");
    assert_eq!(receiver.last_seq(), Some(0));

    let res2 = receiver.receive(&env2, 2, b"msg_2").unwrap();
    assert_eq!(res2, b"Payload 2");
    assert_eq!(receiver.last_seq(), Some(2));

    let res1 = receiver.receive(&env1, 1, b"msg_1").unwrap();
    assert_eq!(res1, b"Payload 1");
    assert_eq!(receiver.last_seq(), Some(2));
}

#[test]
fn test_forged_out_of_order_packet_zero_mutation_attack() {
    let (mut sender, mut receiver) = setup_channel_pair(4);

    let env0 = sender.send(b"Payload 0", b"msg_0").unwrap();
    let env1 = sender.send(b"Payload 1", b"msg_1").unwrap();
    let env2 = sender.send(b"Payload 2", b"msg_2").unwrap();

    receiver.receive(&env0, 0, b"msg_0").unwrap();
    receiver.receive(&env2, 2, b"msg_2").unwrap();
    assert_eq!(receiver.last_seq(), Some(2));

    // ATTACK: Attacker sends a forged packet targeting seq=1 by corrupting envelope slots
    let mut forged_env1 = env1.clone();
    for env in forged_env1.iter_mut() {
        env[20] ^= 0xFF;
    }

    let attack_res = receiver.receive(&forged_env1, 1, b"msg_1");
    assert_eq!(attack_res.err(), Some(ChannelError::AuthenticationFailed));
    assert_eq!(receiver.last_seq(), Some(2));

    // Genuine seq=1 packet arrives later -> MUST STILL SUCCEED!
    let genuine_res = receiver.receive(&env1, 1, b"msg_1").unwrap();
    assert_eq!(genuine_res, b"Payload 1");
    assert_eq!(receiver.last_seq(), Some(2));
}

#[test]
fn test_forged_forward_packet_zero_mutation_attack() {
    let (mut sender, mut receiver) = setup_channel_pair(4);

    let env0 = sender.send(b"Payload 0", b"msg_0").unwrap();
    receiver.receive(&env0, 0, b"msg_0").unwrap();
    assert_eq!(receiver.last_seq(), Some(0));

    // Generate valid envelopes for seq 1..5 on sender side
    let _env1 = sender.send(b"Payload 1", b"msg_1").unwrap();
    let _env2 = sender.send(b"Payload 2", b"msg_2").unwrap();
    let _env3 = sender.send(b"Payload 3", b"msg_3").unwrap();
    let _env4 = sender.send(b"Payload 4", b"msg_4").unwrap();
    let env5 = sender.send(b"Payload 5", b"msg_5").unwrap();

    // ATTACK: Attacker sends a forged packet targeting forward jump seq=5 by corrupting envelope slots
    let mut forged_env5 = env5.clone();
    for env in forged_env5.iter_mut() {
        env[20] ^= 0xAA;
    }

    let attack_res = receiver.receive(&forged_env5, 5, b"msg_5");
    assert_eq!(attack_res.err(), Some(ChannelError::AuthenticationFailed));
    // Receiver last_seq MUST REMAIN AT Some(0), NOT Some(5)!
    assert_eq!(receiver.last_seq(), Some(0));

    // Genuine seq=5 packet arrives later -> MUST STILL SUCCEED!
    let genuine_res = receiver.receive(&env5, 5, b"msg_5").unwrap();
    assert_eq!(genuine_res, b"Payload 5");
    assert_eq!(receiver.last_seq(), Some(5));
}

#[test]
fn test_replayed_sequence_rejected() {
    let (mut sender, mut receiver) = setup_channel_pair(4);

    let env0 = sender.send(b"Payload 0", b"msg_0").unwrap();
    receiver.receive(&env0, 0, b"msg_0").unwrap();

    let res_dup = receiver.receive(&env0, 0, b"msg_0");
    assert_eq!(res_dup.err(), Some(ChannelError::ReplayedSequence));
}

#[test]
fn test_max_skip_window_exceeded() {
    let (mut sender, mut receiver) = setup_channel_pair(4);

    let env0 = sender.send(b"Payload 0", b"msg_0").unwrap();
    receiver.receive(&env0, 0, b"msg_0").unwrap();

    let out_of_bounds_seq = (MAX_SKIP_WINDOW + 2) as u64;
    let dummy_env = vec![[0u8; 1024]; 4];

    let result = receiver.receive(&dummy_env, out_of_bounds_seq, b"msg_huge");
    assert_eq!(result.err(), Some(ChannelError::InvalidSequence));
}

#[test]
fn test_oversized_message_id_rejected() {
    let (mut sender, mut receiver) = setup_channel_pair(4);
    let oversized_msg_id = vec![0x33u8; 257];

    let send_res = sender.send(b"Payload", &oversized_msg_id);
    assert_eq!(send_res.err(), Some(ChannelError::InvalidMessageId));

    let dummy_env = vec![[0u8; 1024]; 4];
    let recv_res = receiver.receive(&dummy_env, 0, &oversized_msg_id);
    assert_eq!(recv_res.err(), Some(ChannelError::InvalidMessageId));
}
