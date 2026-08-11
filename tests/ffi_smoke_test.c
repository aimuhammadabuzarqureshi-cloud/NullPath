/**
 * @file ffi_smoke_test.c
 * @brief NullPath / DecoyPath C ABI Integration & Memory Safety Smoke Test
 *
 * Exercises the full handshake, key agreement, multi-path envelope generation,
 * and decryption workflow across the C ABI boundary exposed by include/decoypath.h.
 */

#include "../include/decoypath.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_OK(expr, msg) \
    do { \
        int32_t _code = (expr); \
        if (_code != DECOYPATH_OK) { \
            fprintf(stderr, "FAIL: %s (Error code: %d)\n", (msg), _code); \
            return 1; \
        } \
    } while (0)

int main(void) {
    printf("[+] Starting NullPath C ABI Smoke Test...\n");

    /* 1. Verify ABI Version */
    int32_t version = decoypath_abi_version();
    printf("    ABI Version: %d\n", version);
    if (version != 1) {
        fprintf(stderr, "FAIL: Unexpected ABI version: %d\n", version);
        return 1;
    }

    /* 2. Generate Initiator & Responder Identity Keypairs */
    uint8_t init_priv[32], init_pub[32];
    uint8_t resp_priv[32], resp_pub[32];

    ASSERT_OK(decoypath_generate_identity_keypair(init_priv, init_pub),
              "Failed to generate Initiator keypair");
    ASSERT_OK(decoypath_generate_identity_keypair(resp_priv, resp_pub),
              "Failed to generate Responder keypair");
    printf("    Identity Keypairs generated successfully.\n");

    /* 3. Initiator Initiates Handshake */
    DecoypathInitiatorState *init_state = NULL;
    uint8_t init_payload[DECOYPATH_INIT_PAYLOAD_LEN];
    size_t init_payload_len = sizeof(init_payload);

    ASSERT_OK(decoypath_initiator_initiate(
                  init_priv, resp_pub, &init_state, init_payload, &init_payload_len),
              "Initiator initiate failed");
    if (init_state == NULL || init_payload_len != DECOYPATH_INIT_PAYLOAD_LEN) {
        fprintf(stderr, "FAIL: Invalid initiator output state/payload\n");
        return 1;
    }
    printf("    Handshake initiation payload generated (144 bytes).\n");

    /* 4. Responder Responds to Handshake */
    DecoypathChannel *resp_channel = NULL;
    uint8_t resp_payload[DECOYPATH_RESP_PAYLOAD_LEN];
    size_t resp_payload_len = sizeof(resp_payload);
    size_t n_paths = 4;

    ASSERT_OK(decoypath_responder_respond(
                  resp_priv, init_pub, init_payload, init_payload_len,
                  resp_payload, &resp_payload_len, &resp_channel, n_paths),
              "Responder respond failed");
    if (resp_channel == NULL || resp_payload_len != DECOYPATH_RESP_PAYLOAD_LEN) {
        fprintf(stderr, "FAIL: Invalid responder channel/payload\n");
        return 1;
    }
    printf("    Handshake response payload generated (144 bytes).\n");

    /* 5. Initiator Finalizes Handshake */
    DecoypathChannel *init_channel = NULL;

    /* Note: decoypath_initiator_finalize unconditionally takes ownership of init_state */
    ASSERT_OK(decoypath_initiator_finalize(
                  init_state, resp_payload, resp_payload_len, &init_channel, n_paths),
              "Initiator finalize failed");
    if (init_channel == NULL) {
        fprintf(stderr, "FAIL: Invalid initiator channel output\n");
        return 1;
    }
    printf("    Mutual authentication complete. Root keys matched.\n");

    /* 6. Channel Messaging Exchange */
    const char *test_msg = "NullPath C ABI End-to-End Encrypted Payload";
    size_t payload_len = strlen(test_msg);
    const char *msg_id = "smoke_msg_001";
    size_t msg_id_len = strlen(msg_id);

    size_t envelopes_buf_size = n_paths * DECOYPATH_ENVELOPE_LEN;
    uint8_t *envelopes = (uint8_t *)malloc(envelopes_buf_size);
    size_t envelopes_len = envelopes_buf_size;

    ASSERT_OK(decoypath_channel_send(
                  init_channel, (const uint8_t *)test_msg, payload_len,
                  (const uint8_t *)msg_id, msg_id_len, envelopes, &envelopes_len),
              "Channel send failed");
    if (envelopes_len != envelopes_buf_size) {
        fprintf(stderr, "FAIL: Unexpected envelope output length\n");
        free(envelopes);
        return 1;
    }
    printf("    Multi-path envelopes sealed (%zu bytes across %zu slots).\n",
           envelopes_len, n_paths);

    /* 7. Receive & Authenticate Envelopes at Responder */
    uint8_t decrypted_buf[DECOYPATH_MAX_PAYLOAD_SIZE];
    size_t decrypted_len = sizeof(decrypted_buf);

    ASSERT_OK(decoypath_channel_receive(
                  resp_channel, envelopes, envelopes_len, 0,
                  (const uint8_t *)msg_id, msg_id_len, decrypted_buf, &decrypted_len),
              "Channel receive failed");

    if (decrypted_len != payload_len || memcmp(decrypted_buf, test_msg, payload_len) != 0) {
        fprintf(stderr, "FAIL: Decrypted payload mismatch\n");
        free(envelopes);
        return 1;
    }
    printf("    Decrypted payload matches original: \"%.*s\"\n",
           (int)decrypted_len, decrypted_buf);

    /* 8. Replay Rejection Verification */
    int32_t dup_res = decoypath_channel_receive(
        resp_channel, envelopes, envelopes_len, 0,
        (const uint8_t *)msg_id, msg_id_len, decrypted_buf, &decrypted_len);
    if (dup_res != DECOYPATH_ERR_REPLAYED_SEQUENCE) {
        fprintf(stderr, "FAIL: Expected DECOYPATH_ERR_REPLAYED_SEQUENCE, got %d\n", dup_res);
        free(envelopes);
        return 1;
    }
    printf("    Replay rejection verified (DECOYPATH_ERR_REPLAYED_SEQUENCE).\n");

    /* Cleanup Memory */
    free(envelopes);
    decoypath_channel_free(init_channel);
    decoypath_channel_free(resp_channel);

    /* Zeroize local secret buffers before exit */
    memset(init_priv, 0, sizeof(init_priv));
    memset(resp_priv, 0, sizeof(resp_priv));
    memset(decrypted_buf, 0, sizeof(decrypted_buf));

    printf("[+] ALL C ABI SMOKE TESTS PASSED CLEANLY.\n");
    return 0;
}
