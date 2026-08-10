//! # C-Boundary Memory Safety & Zeroization Warning
//!
//! Data transferred across the C ABI boundary into caller-allocated raw buffers (e.g. key material in
//! `decoypath_generate_identity_keypair` or plaintext in `decoypath_channel_receive`) moves out of Rust's
//! lifetime tracking and `Zeroize` drop handlers. The calling C/C++ application is strictly responsible
//! for zeroizing sensitive secret keys and decrypted plaintext buffers when they are no longer needed.

use std::panic::catch_unwind;
use std::slice;
use zeroize::Zeroize;

use crate::channel::{SecureChannel, MAX_MESSAGE_ID_LEN};
use crate::crypto::generate_identity_keypair;
use crate::envelope::{ENVELOPE_TOTAL_LEN, MAX_PAYLOAD_SIZE};
use crate::errors::ChannelError;
use crate::handshake::{InitiatorState, ResponderState};
use crate::types::{
    HandshakeInitPayload, HandshakeResponsePayload, IdentityPrivateKey, RootKey, INIT_PAYLOAD_LEN,
    RESP_PAYLOAD_LEN,
};

/// Maximum allowed paths per multi-path envelope set (64 paths = 65,536 bytes).
pub const MAX_N_PATHS: usize = 64;

/// FFI Return Codes
pub const DECOYPATH_OK: i32 = 0;
pub const DECOYPATH_ERR_NULL_POINTER: i32 = -1;
pub const DECOYPATH_ERR_INVALID_PAYLOAD: i32 = -2;
pub const DECOYPATH_ERR_AUTHENTICATION_FAILED: i32 = -3;
pub const DECOYPATH_ERR_CRYPTO_FAILURE: i32 = -4;
pub const DECOYPATH_ERR_BUFFER_TOO_SMALL: i32 = -5;
pub const DECOYPATH_ERR_INVALID_SEQUENCE: i32 = -6;
pub const DECOYPATH_ERR_REPLAYED_SEQUENCE: i32 = -7;
pub const DECOYPATH_ERR_SKIPPED_KEY_EXPIRED: i32 = -8;
pub const DECOYPATH_ERR_INVALID_MESSAGE_ID: i32 = -9;
pub const DECOYPATH_ERR_PANIC: i32 = -99;

/// Opaque wrapper for InitiatorState across C ABI boundary.
pub struct DecoypathInitiatorState(pub(crate) InitiatorState);

/// Opaque wrapper for SecureChannel across C ABI boundary.
pub struct DecoypathChannel(pub(crate) SecureChannel);

/// Returns the C ABI library version number (1).
#[no_mangle]
pub unsafe extern "C" fn decoypath_abi_version() -> i32 {
    1
}

/// Generates a fresh Ed25519 identity keypair into caller-allocated 32-byte buffers.
///
/// # Safety
/// Caller must pass non-null valid pointers `out_priv` and `out_pub` of at least 32 bytes each.
#[no_mangle]
pub unsafe extern "C" fn decoypath_generate_identity_keypair(
    out_priv: *mut u8,
    out_pub: *mut u8,
) -> i32 {
    let result = catch_unwind(|| {
        if out_priv.is_null() || out_pub.is_null() {
            return DECOYPATH_ERR_NULL_POINTER;
        }

        let (priv_key, pub_key) = generate_identity_keypair();
        let priv_slice = slice::from_raw_parts_mut(out_priv, 32);
        let pub_slice = slice::from_raw_parts_mut(out_pub, 32);

        priv_slice.copy_from_slice(&priv_key.0.to_bytes());
        pub_slice.copy_from_slice(pub_key.as_bytes());

        DECOYPATH_OK
    });

    result.unwrap_or(DECOYPATH_ERR_PANIC)
}

/// Initiates a handshake session, creating an opaque `DecoypathInitiatorState` object.
///
/// # Safety
/// Caller must pass valid pointers for all arguments. `out_payload_len` must point to allocated buffer capacity.
#[no_mangle]
pub unsafe extern "C" fn decoypath_initiator_initiate(
    init_priv: *const u8,
    resp_pub: *const u8,
    out_state: *mut *mut DecoypathInitiatorState,
    out_payload: *mut u8,
    out_payload_len: *mut usize,
) -> i32 {
    let result = catch_unwind(|| {
        if init_priv.is_null()
            || resp_pub.is_null()
            || out_state.is_null()
            || out_payload.is_null()
            || out_payload_len.is_null()
        {
            return DECOYPATH_ERR_NULL_POINTER;
        }

        if *out_payload_len < INIT_PAYLOAD_LEN {
            *out_payload_len = INIT_PAYLOAD_LEN;
            return DECOYPATH_ERR_BUFFER_TOO_SMALL;
        }

        let priv_bytes: [u8; 32] = match slice::from_raw_parts(init_priv, 32).try_into() {
            Ok(arr) => arr,
            Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
        };
        let pub_bytes: [u8; 32] = match slice::from_raw_parts(resp_pub, 32).try_into() {
            Ok(arr) => arr,
            Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
        };

        let priv_key = IdentityPrivateKey::new(priv_bytes);
        let pub_key = match ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes) {
            Ok(vk) => vk,
            Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
        };

        let (state, payload) = InitiatorState::initiate(priv_key, pub_key);

        let payload_slice = slice::from_raw_parts_mut(out_payload, INIT_PAYLOAD_LEN);
        payload_slice.copy_from_slice(&payload.to_bytes());
        *out_payload_len = INIT_PAYLOAD_LEN;

        let state_box = Box::new(DecoypathInitiatorState(state));
        *out_state = Box::into_raw(state_box);

        DECOYPATH_OK
    });

    result.unwrap_or(DECOYPATH_ERR_PANIC)
}

/// Responds to a handshake initiation payload, creating an opaque `DecoypathChannel` object.
///
/// # Safety
/// Caller must pass valid pointers for all arguments. `expected_init_pub` may be null for unauthenticated responder.
#[no_mangle]
pub unsafe extern "C" fn decoypath_responder_respond(
    resp_priv: *const u8,
    expected_init_pub: *const u8,
    init_payload: *const u8,
    init_payload_len: usize,
    out_payload: *mut u8,
    out_payload_len: *mut usize,
    out_channel: *mut *mut DecoypathChannel,
    n_paths: usize,
) -> i32 {
    let result = catch_unwind(|| {
        if resp_priv.is_null()
            || init_payload.is_null()
            || out_payload.is_null()
            || out_payload_len.is_null()
            || out_channel.is_null()
        {
            return DECOYPATH_ERR_NULL_POINTER;
        }

        if init_payload_len != INIT_PAYLOAD_LEN {
            return DECOYPATH_ERR_INVALID_PAYLOAD;
        }

        if *out_payload_len < RESP_PAYLOAD_LEN {
            *out_payload_len = RESP_PAYLOAD_LEN;
            return DECOYPATH_ERR_BUFFER_TOO_SMALL;
        }

        if n_paths == 0 || n_paths > MAX_N_PATHS {
            return DECOYPATH_ERR_INVALID_PAYLOAD;
        }

        let priv_bytes: [u8; 32] = match slice::from_raw_parts(resp_priv, 32).try_into() {
            Ok(arr) => arr,
            Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
        };
        let priv_key = IdentityPrivateKey::new(priv_bytes);

        let expected_pub = if !expected_init_pub.is_null() {
            let bytes: [u8; 32] = match slice::from_raw_parts(expected_init_pub, 32).try_into() {
                Ok(arr) => arr,
                Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
            };
            match ed25519_dalek::VerifyingKey::from_bytes(&bytes) {
                Ok(vk) => Some(vk),
                Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
            }
        } else {
            None
        };

        let init_payload_slice = slice::from_raw_parts(init_payload, INIT_PAYLOAD_LEN);
        let init_payload_struct = match HandshakeInitPayload::from_bytes(init_payload_slice) {
            Ok(p) => p,
            Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
        };

        let (resp_payload, root_key) =
            match ResponderState::respond(&priv_key, expected_pub.as_ref(), &init_payload_struct) {
                Ok(res) => res,
                Err(_) => return DECOYPATH_ERR_AUTHENTICATION_FAILED,
            };

        let payload_slice = slice::from_raw_parts_mut(out_payload, RESP_PAYLOAD_LEN);
        payload_slice.copy_from_slice(&resp_payload.to_bytes());
        *out_payload_len = RESP_PAYLOAD_LEN;

        let channel = SecureChannel::new(root_key, n_paths);
        let channel_box = Box::new(DecoypathChannel(channel));
        *out_channel = Box::into_raw(channel_box);

        DECOYPATH_OK
    });

    result.unwrap_or(DECOYPATH_ERR_PANIC)
}

/// Finalizes the initiator handshake session using responder payload, creating a `DecoypathChannel`.
///
/// # Safety
/// Takes ownership of non-null `state` pointer immediately after null check and frees it upon exit on
/// BOTH success and failure paths. The caller must NEVER call `decoypath_initiator_state_free` on this
/// pointer after calling this function.
#[no_mangle]
pub unsafe extern "C" fn decoypath_initiator_finalize(
    state: *mut DecoypathInitiatorState,
    resp_payload: *const u8,
    resp_payload_len: usize,
    out_channel: *mut *mut DecoypathChannel,
    n_paths: usize,
) -> i32 {
    let result = catch_unwind(|| {
        if state.is_null() || resp_payload.is_null() || out_channel.is_null() {
            return DECOYPATH_ERR_NULL_POINTER;
        }

        // UNCONDITIONAL OWNERSHIP TRANSFER: Take Box ownership immediately after null check
        let state_box = Box::from_raw(state);

        if resp_payload_len != RESP_PAYLOAD_LEN {
            return DECOYPATH_ERR_INVALID_PAYLOAD;
        }

        if n_paths == 0 || n_paths > MAX_N_PATHS {
            return DECOYPATH_ERR_INVALID_PAYLOAD;
        }

        let resp_payload_slice = slice::from_raw_parts(resp_payload, RESP_PAYLOAD_LEN);
        let resp_payload_struct = match HandshakeResponsePayload::from_bytes(resp_payload_slice) {
            Ok(p) => p,
            Err(_) => return DECOYPATH_ERR_INVALID_PAYLOAD,
        };

        let root_key: RootKey = match state_box.0.finalize(&resp_payload_struct) {
            Ok(rk) => rk,
            Err(_) => return DECOYPATH_ERR_AUTHENTICATION_FAILED,
        };

        let channel = SecureChannel::new(root_key, n_paths);
        let channel_box = Box::new(DecoypathChannel(channel));
        *out_channel = Box::into_raw(channel_box);

        DECOYPATH_OK
    });

    result.unwrap_or(DECOYPATH_ERR_PANIC)
}

/// Encrypts and packs a payload into multi-path envelope buffers across C ABI boundary.
///
/// # Safety
/// Caller must pass valid non-null pointers and allocated buffer memory.
#[no_mangle]
pub unsafe extern "C" fn decoypath_channel_send(
    channel: *mut DecoypathChannel,
    payload: *const u8,
    payload_len: usize,
    message_id: *const u8,
    message_id_len: usize,
    out_envelopes: *mut u8,
    out_envelopes_len: *mut usize,
) -> i32 {
    let result = catch_unwind(|| {
        if channel.is_null()
            || payload.is_null()
            || message_id.is_null()
            || out_envelopes.is_null()
            || out_envelopes_len.is_null()
        {
            return DECOYPATH_ERR_NULL_POINTER;
        }

        if payload_len > MAX_PAYLOAD_SIZE {
            return DECOYPATH_ERR_INVALID_PAYLOAD;
        }

        if message_id_len > MAX_MESSAGE_ID_LEN {
            return DECOYPATH_ERR_INVALID_MESSAGE_ID;
        }

        let channel_ref = &mut (*channel).0;
        let payload_slice = slice::from_raw_parts(payload, payload_len);
        let msg_id_slice = slice::from_raw_parts(message_id, message_id_len);

        let envelopes = match channel_ref.send(payload_slice, msg_id_slice) {
            Ok(env) => env,
            Err(ChannelError::InvalidMessageId) => return DECOYPATH_ERR_INVALID_MESSAGE_ID,
            Err(ChannelError::InvalidSequence) => return DECOYPATH_ERR_INVALID_SEQUENCE,
            Err(_) => return DECOYPATH_ERR_CRYPTO_FAILURE,
        };

        let required_len = envelopes.len() * ENVELOPE_TOTAL_LEN;
        if *out_envelopes_len < required_len {
            *out_envelopes_len = required_len;
            return DECOYPATH_ERR_BUFFER_TOO_SMALL;
        }

        let out_slice = slice::from_raw_parts_mut(out_envelopes, required_len);
        for (i, env) in envelopes.iter().enumerate() {
            let start = i * ENVELOPE_TOTAL_LEN;
            out_slice[start..start + ENVELOPE_TOTAL_LEN].copy_from_slice(env);
        }
        *out_envelopes_len = required_len;

        DECOYPATH_OK
    });

    result.unwrap_or(DECOYPATH_ERR_PANIC)
}

/// Receives, authenticates, and decrypts multi-path envelope buffers across C ABI boundary.
///
/// # Safety
/// Caller must pass valid non-null pointers and allocated buffer memory.
#[no_mangle]
pub unsafe extern "C" fn decoypath_channel_receive(
    channel: *mut DecoypathChannel,
    envelopes: *const u8,
    envelopes_len: usize,
    seq: u64,
    message_id: *const u8,
    message_id_len: usize,
    out_payload: *mut u8,
    out_payload_len: *mut usize,
) -> i32 {
    let result = catch_unwind(|| {
        if channel.is_null()
            || envelopes.is_null()
            || message_id.is_null()
            || out_payload.is_null()
            || out_payload_len.is_null()
        {
            return DECOYPATH_ERR_NULL_POINTER;
        }

        if message_id_len > MAX_MESSAGE_ID_LEN {
            return DECOYPATH_ERR_INVALID_MESSAGE_ID;
        }

        if envelopes_len == 0
            || envelopes_len % ENVELOPE_TOTAL_LEN != 0
            || envelopes_len > MAX_N_PATHS * ENVELOPE_TOTAL_LEN
        {
            return DECOYPATH_ERR_INVALID_PAYLOAD;
        }

        let n_paths = envelopes_len / ENVELOPE_TOTAL_LEN;
        let env_raw_slice = slice::from_raw_parts(envelopes, envelopes_len);
        let mut envelope_vec = Vec::with_capacity(n_paths);

        for i in 0..n_paths {
            let start = i * ENVELOPE_TOTAL_LEN;
            let mut env = [0u8; ENVELOPE_TOTAL_LEN];
            env.copy_from_slice(&env_raw_slice[start..start + ENVELOPE_TOTAL_LEN]);
            envelope_vec.push(env);
        }

        let channel_ref = &mut (*channel).0;
        let msg_id_slice = slice::from_raw_parts(message_id, message_id_len);

        let mut decrypted = match channel_ref.receive(&envelope_vec, seq, msg_id_slice) {
            Ok(p) => p,
            Err(ChannelError::ReplayedSequence) => return DECOYPATH_ERR_REPLAYED_SEQUENCE,
            Err(ChannelError::SkippedKeyExpired) => return DECOYPATH_ERR_SKIPPED_KEY_EXPIRED,
            Err(ChannelError::InvalidSequence) => return DECOYPATH_ERR_INVALID_SEQUENCE,
            Err(ChannelError::InvalidMessageId) => return DECOYPATH_ERR_INVALID_MESSAGE_ID,
            Err(ChannelError::AuthenticationFailed) => return DECOYPATH_ERR_AUTHENTICATION_FAILED,
            Err(_) => return DECOYPATH_ERR_CRYPTO_FAILURE,
        };

        if *out_payload_len < decrypted.len() {
            *out_payload_len = decrypted.len();
            // Zeroize intermediate decrypted plaintext buffer before returning error
            decrypted.zeroize();
            return DECOYPATH_ERR_BUFFER_TOO_SMALL;
        }

        let out_slice = slice::from_raw_parts_mut(out_payload, decrypted.len());
        out_slice.copy_from_slice(&decrypted);
        *out_payload_len = decrypted.len();

        // Zeroize Rust-owned intermediate after copying out
        decrypted.zeroize();

        DECOYPATH_OK
    });

    result.unwrap_or(DECOYPATH_ERR_PANIC)
}

/// Frees an un-finalized `DecoypathInitiatorState` pointer.
///
/// # Safety
/// `state` must be a valid pointer created by `decoypath_initiator_initiate` or null.
#[no_mangle]
pub unsafe extern "C" fn decoypath_initiator_state_free(state: *mut DecoypathInitiatorState) {
    let _ = catch_unwind(|| {
        if !state.is_null() {
            let _ = Box::from_raw(state);
        }
    });
}

/// Frees a `DecoypathChannel` pointer.
///
/// # Safety
/// `channel` must be a valid pointer created by responder/initiator finalize functions or null.
#[no_mangle]
pub unsafe extern "C" fn decoypath_channel_free(channel: *mut DecoypathChannel) {
    let _ = catch_unwind(|| {
        if !channel.is_null() {
            let _ = Box::from_raw(channel);
        }
    });
}
