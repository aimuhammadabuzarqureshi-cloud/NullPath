use decoypath::*;

#[test]
fn test_ffi_abi_version() {
    unsafe {
        assert_eq!(decoypath_abi_version(), 1);
    }
}

#[test]
fn test_ffi_end_to_end_handshake_and_channel() {
    unsafe {
        // 1. Generate identity keypairs
        let mut init_priv = [0u8; 32];
        let mut init_pub = [0u8; 32];
        let mut resp_priv = [0u8; 32];
        let mut resp_pub = [0u8; 32];

        assert_eq!(
            decoypath_generate_identity_keypair(init_priv.as_mut_ptr(), init_pub.as_mut_ptr()),
            DECOYPATH_OK
        );
        assert_eq!(
            decoypath_generate_identity_keypair(resp_priv.as_mut_ptr(), resp_pub.as_mut_ptr()),
            DECOYPATH_OK
        );

        // 2. Initiator initiate
        let mut init_state_ptr: *mut DecoypathInitiatorState = std::ptr::null_mut();
        let mut init_payload = [0u8; INIT_PAYLOAD_LEN];
        let mut init_payload_len = init_payload.len();

        assert_eq!(
            decoypath_initiator_initiate(
                init_priv.as_ptr(),
                resp_pub.as_ptr(),
                &mut init_state_ptr,
                init_payload.as_mut_ptr(),
                &mut init_payload_len
            ),
            DECOYPATH_OK
        );
        assert!(!init_state_ptr.is_null());
        assert_eq!(init_payload_len, INIT_PAYLOAD_LEN);

        // 3. Responder respond
        let mut resp_channel_ptr: *mut DecoypathChannel = std::ptr::null_mut();
        let mut resp_payload = [0u8; RESP_PAYLOAD_LEN];
        let mut resp_payload_len = resp_payload.len();

        assert_eq!(
            decoypath_responder_respond(
                resp_priv.as_ptr(),
                init_pub.as_ptr(),
                init_payload.as_ptr(),
                init_payload_len,
                resp_payload.as_mut_ptr(),
                &mut resp_payload_len,
                &mut resp_channel_ptr,
                4
            ),
            DECOYPATH_OK
        );
        assert!(!resp_channel_ptr.is_null());
        assert_eq!(resp_payload_len, RESP_PAYLOAD_LEN);

        // 4. Initiator finalize
        let mut init_channel_ptr: *mut DecoypathChannel = std::ptr::null_mut();

        assert_eq!(
            decoypath_initiator_finalize(
                init_state_ptr,
                resp_payload.as_ptr(),
                resp_payload_len,
                &mut init_channel_ptr,
                4
            ),
            DECOYPATH_OK
        );
        assert!(!init_channel_ptr.is_null());

        // 5. Channel message exchange across FFI boundary
        let payload = b"Hello over C ABI!";
        let msg_id = b"msg_ffi_0";

        let mut envelopes_buf = vec![0u8; 4 * ENVELOPE_TOTAL_LEN];
        let mut envelopes_len = envelopes_buf.len();

        assert_eq!(
            decoypath_channel_send(
                init_channel_ptr,
                payload.as_ptr(),
                payload.len(),
                msg_id.as_ptr(),
                msg_id.len(),
                envelopes_buf.as_mut_ptr(),
                &mut envelopes_len
            ),
            DECOYPATH_OK
        );
        assert_eq!(envelopes_len, 4 * ENVELOPE_TOTAL_LEN);

        let mut out_payload = vec![0u8; 992];
        let mut out_payload_len = out_payload.len();

        assert_eq!(
            decoypath_channel_receive(
                resp_channel_ptr,
                envelopes_buf.as_ptr(),
                envelopes_len,
                0,
                msg_id.as_ptr(),
                msg_id.len(),
                out_payload.as_mut_ptr(),
                &mut out_payload_len
            ),
            DECOYPATH_OK
        );

        assert_eq!(&out_payload[..out_payload_len], payload);

        // 6. Test granular error: Replaying seq 0 returns DECOYPATH_ERR_REPLAYED_SEQUENCE
        let mut dup_payload = vec![0u8; 992];
        let mut dup_payload_len = dup_payload.len();

        assert_eq!(
            decoypath_channel_receive(
                resp_channel_ptr,
                envelopes_buf.as_ptr(),
                envelopes_len,
                0,
                msg_id.as_ptr(),
                msg_id.len(),
                dup_payload.as_mut_ptr(),
                &mut dup_payload_len
            ),
            DECOYPATH_ERR_REPLAYED_SEQUENCE
        );

        // 7. Test oversized message_id_len (257 bytes) returns DECOYPATH_ERR_INVALID_MESSAGE_ID with valid channel
        let oversized_msg_id = vec![0xEEu8; 257];
        let mut send_out_len = 4 * ENVELOPE_TOTAL_LEN;
        let mut send_env_buf = vec![0u8; send_out_len];

        assert_eq!(
            decoypath_channel_send(
                init_channel_ptr,
                payload.as_ptr(),
                payload.len(),
                oversized_msg_id.as_ptr(),
                oversized_msg_id.len(),
                send_env_buf.as_mut_ptr(),
                &mut send_out_len
            ),
            DECOYPATH_ERR_INVALID_MESSAGE_ID
        );

        // 8. Free channel pointers
        decoypath_channel_free(init_channel_ptr);
        decoypath_channel_free(resp_channel_ptr);
    }
}

#[test]
fn test_ffi_null_pointer_rejection() {
    unsafe {
        assert_eq!(
            decoypath_generate_identity_keypair(std::ptr::null_mut(), std::ptr::null_mut()),
            DECOYPATH_ERR_NULL_POINTER
        );

        let mut out_channel: *mut DecoypathChannel = std::ptr::null_mut();
        assert_eq!(
            decoypath_initiator_finalize(
                std::ptr::null_mut(),
                std::ptr::null(),
                RESP_PAYLOAD_LEN,
                &mut out_channel,
                4
            ),
            DECOYPATH_ERR_NULL_POINTER
        );
    }
}
