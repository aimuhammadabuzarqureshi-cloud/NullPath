#ifndef DECOYPATH_H
#define DECOYPATH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FFI Error Codes */
#define DECOYPATH_OK                          0
#define DECOYPATH_ERR_NULL_POINTER           -1
#define DECOYPATH_ERR_INVALID_PAYLOAD        -2
#define DECOYPATH_ERR_AUTHENTICATION_FAILED  -3
#define DECOYPATH_ERR_CRYPTO_FAILURE         -4
#define DECOYPATH_ERR_BUFFER_TOO_SMALL       -5
#define DECOYPATH_ERR_INVALID_SEQUENCE       -6
#define DECOYPATH_ERR_REPLAYED_SEQUENCE      -7
#define DECOYPATH_ERR_SKIPPED_KEY_EXPIRED    -8
#define DECOYPATH_ERR_INVALID_MESSAGE_ID     -9
#define DECOYPATH_ERR_PANIC                 -99

/* Constants */
#define DECOYPATH_INIT_PAYLOAD_LEN 144
#define DECOYPATH_RESP_PAYLOAD_LEN 144
#define DECOYPATH_ENVELOPE_LEN     1024
#define DECOYPATH_MAX_PAYLOAD_SIZE 992
#define DECOYPATH_MAX_MESSAGE_ID   256
#define DECOYPATH_MAX_N_PATHS      64

/* Opaque handles */
typedef struct DecoypathInitiatorState DecoypathInitiatorState;
typedef struct DecoypathChannel DecoypathChannel;

/* Returns ABI version number (1) */
int32_t decoypath_abi_version(void);

/* Generates fresh Ed25519 identity keypair into caller-allocated 32-byte buffers */
int32_t decoypath_generate_identity_keypair(uint8_t *out_priv, uint8_t *out_pub);

/* Initiates handshake session */
int32_t decoypath_initiator_initiate(
    const uint8_t *init_priv,
    const uint8_t *resp_pub,
    DecoypathInitiatorState **out_state,
    uint8_t *out_payload,
    size_t *out_payload_len
);

/* Responds to handshake initiation payload */
int32_t decoypath_responder_respond(
    const uint8_t *resp_priv,
    const uint8_t *expected_init_pub,
    const uint8_t *init_payload,
    size_t init_payload_len,
    uint8_t *out_payload,
    size_t *out_payload_len,
    DecoypathChannel **out_channel,
    size_t n_paths
);

/* Finalizes initiator handshake session. ALWAYS consumes and frees state handle on success or failure. */
int32_t decoypath_initiator_finalize(
    DecoypathInitiatorState *state,
    const uint8_t *resp_payload,
    size_t resp_payload_len,
    DecoypathChannel **out_channel,
    size_t n_paths
);

/* Encrypts and distributes payload into multi-path envelopes */
int32_t decoypath_channel_send(
    DecoypathChannel *channel,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *message_id,
    size_t message_id_len,
    uint8_t *out_envelopes,
    size_t *out_envelopes_len
);

/* Receives and decrypts multi-path envelopes */
int32_t decoypath_channel_receive(
    DecoypathChannel *channel,
    const uint8_t *envelopes,
    size_t envelopes_len,
    uint64_t seq,
    const uint8_t *message_id,
    size_t message_id_len,
    uint8_t *out_payload,
    size_t *out_payload_len
);

/* Frees un-finalized initiator state handle */
void decoypath_initiator_state_free(DecoypathInitiatorState *state);

/* Frees channel handle */
void decoypath_channel_free(DecoypathChannel *channel);

#ifdef __cplusplus
}
#endif

#endif /* DECOYPATH_H */
