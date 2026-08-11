pub mod anti_replay;
pub mod channel;
pub mod crypto;
pub mod decoy;
pub mod envelope;
pub mod errors;
#[cfg(feature = "cffi")]
pub mod ffi;
pub mod handshake;
pub mod path_engine;
pub mod types;

pub use anti_replay::AntiReplayStore;
pub use channel::{SecureChannel, MAX_MESSAGE_ID_LEN, MAX_SKIPPED_KEYS, MAX_SKIP_WINDOW};
pub use crypto::generate_identity_keypair;
pub use decoy::{generate_decoy, generate_multi_path_slots};
pub use envelope::{open, seal, ENVELOPE_TOTAL_LEN, MAX_PAYLOAD_SIZE};
pub use errors::{ChannelError, DecoyError, EnvelopeError, HandshakeError, PathEngineError};
#[cfg(feature = "cffi")]
pub use ffi::{
    decoypath_abi_version, decoypath_channel_free, decoypath_channel_receive, decoypath_channel_send,
    decoypath_generate_identity_keypair, decoypath_initiator_finalize, decoypath_initiator_initiate,
    decoypath_initiator_state_free, decoypath_responder_respond, DecoypathChannel,
    DecoypathInitiatorState, DECOYPATH_ERR_AUTHENTICATION_FAILED, DECOYPATH_ERR_BUFFER_TOO_SMALL,
    DECOYPATH_ERR_CRYPTO_FAILURE, DECOYPATH_ERR_INVALID_MESSAGE_ID, DECOYPATH_ERR_INVALID_PAYLOAD,
    DECOYPATH_ERR_INVALID_SEQUENCE, DECOYPATH_ERR_NULL_POINTER, DECOYPATH_ERR_PANIC,
    DECOYPATH_ERR_REPLAYED_SEQUENCE, DECOYPATH_ERR_SKIPPED_KEY_EXPIRED, DECOYPATH_OK, MAX_N_PATHS,
};
pub use handshake::{InitiatorState, ResponderState};
pub use path_engine::{select_slot, RatchetKey};
pub use types::{
    HandshakeInitPayload, HandshakeResponsePayload, IdentityPrivateKey, RawDhSecret, RootKey,
    INIT_PAYLOAD_LEN, RESP_PAYLOAD_LEN,
};

