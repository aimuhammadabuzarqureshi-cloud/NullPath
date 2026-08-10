use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::crypto::{
    derive_root_key, generate_nonce, sign_initiation, sign_response, verify_initiation,
    verify_response, EphemeralKeyPair,
};
use crate::errors::HandshakeError;
use crate::types::{HandshakeInitPayload, HandshakeResponsePayload, IdentityPrivateKey, RootKey};

/// State machine for the handshake Initiator.
pub struct InitiatorState {
    identity_pub: Ed25519PublicKey,
    expected_responder_pub: Ed25519PublicKey,
    ephemeral: EphemeralKeyPair,
    ephemeral_pub: X25519PublicKey,
    nonce: [u8; 16],
}

impl InitiatorState {
    /// Step 1: Initiator initializes handshake state and constructs initiation payload.
    pub fn initiate(
        identity_priv: IdentityPrivateKey,
        expected_responder_pub: Ed25519PublicKey,
    ) -> (Self, HandshakeInitPayload) {
        let identity_pub = identity_priv.verifying_key();
        let ephemeral = EphemeralKeyPair::generate();
        let ephemeral_pub = ephemeral.public;
        let nonce = generate_nonce();

        let signature = sign_initiation(&identity_priv, &expected_responder_pub, &ephemeral_pub, &nonce);

        let payload = HandshakeInitPayload {
            initiator_identity_pub: identity_pub,
            initiator_ephemeral_pub: ephemeral_pub,
            nonce,
            signature,
        };

        let state = Self {
            identity_pub,
            expected_responder_pub,
            ephemeral,
            ephemeral_pub,
            nonce,
        };

        (state, payload)
    }

    /// Step 3: Initiator finalizes handshake by processing Responder's response.
    /// CONSUMES `self` BY MOVE so the initiator state and ephemeral key cannot be reused!
    pub fn finalize(
        self,
        response: &HandshakeResponsePayload,
    ) -> Result<RootKey, HandshakeError> {
        // 1. Check responder identity matches locally stored expected key
        if response.responder_identity_pub != self.expected_responder_pub {
            return Err(HandshakeError::PeerIdentityMismatch);
        }

        // 2. Verify Pass 2 signature strictly using self.expected_responder_pub (locally stored key)
        verify_response(
            &self.expected_responder_pub,
            &self.identity_pub,
            &response.responder_ephemeral_pub,
            &self.ephemeral_pub,
            &response.nonce,
            &self.nonce,
            &response.signature,
        )?;

        // 3. Perform Diffie-Hellman exchange (consumes self.ephemeral by move)
        let raw_dh = self.ephemeral.diffie_hellman(&response.responder_ephemeral_pub);

        // 4. Derive RootKey with full transcript binding
        derive_root_key(
            &raw_dh,
            &self.identity_pub,
            &self.expected_responder_pub,
            &self.ephemeral_pub,
            &response.responder_ephemeral_pub,
            &self.nonce,
            &response.nonce,
        )
    }
}

/// Helper methods for Handshake Responder.
pub struct ResponderState;

impl ResponderState {
    /// Step 2: Responder processes initiation, computes DH, derives RootKey, and constructs response payload.
    /// `expected_initiator_pub` is an optional peer identity check if the responder expects a specific initiator.
    pub fn respond(
        responder_identity_priv: &IdentityPrivateKey,
        expected_initiator_pub: Option<&Ed25519PublicKey>,
        initiation: &HandshakeInitPayload,
    ) -> Result<(HandshakeResponsePayload, RootKey), HandshakeError> {
        let responder_identity_pub = responder_identity_priv.verifying_key();

        // 1. If responder specifies expected_initiator_pub, verify match
        if let Some(expected) = expected_initiator_pub {
            if &initiation.initiator_identity_pub != expected {
                return Err(HandshakeError::PeerIdentityMismatch);
            }
        }

        // 2. Verify initiation signature binding expected responder identity
        verify_initiation(
            &initiation.initiator_identity_pub,
            &responder_identity_pub,
            &initiation.initiator_ephemeral_pub,
            &initiation.nonce,
            &initiation.signature,
        )?;

        // 3. Generate responder ephemeral keypair and nonce
        let responder_ephemeral = EphemeralKeyPair::generate();
        let responder_ephemeral_pub = responder_ephemeral.public;
        let responder_nonce = generate_nonce();

        // 4. Sign response payload binding all 6 session parameters
        let signature = sign_response(
            responder_identity_priv,
            &initiation.initiator_identity_pub,
            &responder_ephemeral_pub,
            &initiation.initiator_ephemeral_pub,
            &responder_nonce,
            &initiation.nonce,
        );

        let response_payload = HandshakeResponsePayload {
            responder_identity_pub,
            responder_ephemeral_pub,
            nonce: responder_nonce,
            signature,
        };

        // 5. Perform DH exchange (consumes responder_ephemeral by move)
        let raw_dh = responder_ephemeral.diffie_hellman(&initiation.initiator_ephemeral_pub);

        // 6. Derive RootKey with full transcript binding
        let root_key = derive_root_key(
            &raw_dh,
            &initiation.initiator_identity_pub,
            &responder_identity_pub,
            &initiation.initiator_ephemeral_pub,
            &responder_ephemeral_pub,
            &initiation.nonce,
            &responder_nonce,
        )?;

        Ok((response_payload, root_key))
    }
}
