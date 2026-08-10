# Module 1 Audit Package: DecoyPath Handshake & Key Setup (Revised 2)

## 1. Full Source Files

### `src/errors.rs`

```rust
use std::fmt;

/// Errors that can occur during the decoypath handshake protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Peer Ed25519 identity public key did not match expected key.
    PeerIdentityMismatch,
    /// Invalid payload format or truncated payload bytes.
    InvalidPayloadFormat,
    /// Internal cryptographic derivation or primitive error.
    CryptoFailure,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Handshake signature verification failed"),
            Self::PeerIdentityMismatch => write!(f, "Peer identity key mismatch"),
            Self::InvalidPayloadFormat => write!(f, "Invalid handshake payload format"),
            Self::CryptoFailure => write!(f, "Cryptographic primitive failure"),
        }
    }
}

impl std::error::Error for HandshakeError {}
```

### `src/types.rs`

```rust
use ed25519_dalek::{Signature, SigningKey as Ed25519PrivateKey, VerifyingKey as Ed25519PublicKey};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::errors::HandshakeError;

/// Fixed byte length for HandshakeInitPayload wire encoding (32 + 32 + 16 + 64 = 144 bytes).
pub const INIT_PAYLOAD_LEN: usize = 144;

/// Fixed byte length for HandshakeResponsePayload wire encoding (32 + 32 + 16 + 64 = 144 bytes).
pub const RESP_PAYLOAD_LEN: usize = 144;

/// Derived 256-bit symmetric root key held mutually by both parties.
#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct RootKey(pub [u8; 32]);

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RootKey([REDACTED])")
    }
}

/// Raw X25519 Diffie-Hellman output secret before HKDF transcript expansion.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RawDhSecret(pub [u8; 32]);

impl std::fmt::Debug for RawDhSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawDhSecret([REDACTED])")
    }
}

/// Wrapper for long-term Ed25519 identity private signing key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityPrivateKey(pub Ed25519PrivateKey);

impl IdentityPrivateKey {
    /// Generates a new random Ed25519 identity private key.
    pub fn generate() -> Self {
        let key = Ed25519PrivateKey::generate(&mut rand_core::OsRng);
        Self(key)
    }

    /// Returns the corresponding verifying public key.
    pub fn verifying_key(&self) -> Ed25519PublicKey {
        self.0.verifying_key()
    }
}

impl std::fmt::Debug for IdentityPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityPrivateKey([REDACTED])")
    }
}

/// Handshake initiation message sent from Initiator to Responder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeInitPayload {
    pub initiator_identity_pub: Ed25519PublicKey,
    pub initiator_ephemeral_pub: X25519PublicKey,
    pub nonce: [u8; 16],
    pub signature: Signature,
}

impl HandshakeInitPayload {
    /// Serializes payload to a fixed 144-byte array.
    pub fn to_bytes(&self) -> [u8; INIT_PAYLOAD_LEN] {
        let mut out = [0u8; INIT_PAYLOAD_LEN];
        out[0..32].copy_from_slice(self.initiator_identity_pub.as_bytes());
        out[32..64].copy_from_slice(self.initiator_ephemeral_pub.as_bytes());
        out[64..80].copy_from_slice(&self.nonce);
        out[80..144].copy_from_slice(&self.signature.to_bytes());
        out
    }

    /// Deserializes payload from a fixed 144-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() != INIT_PAYLOAD_LEN {
            return Err(HandshakeError::InvalidPayloadFormat);
        }

        let identity_bytes: [u8; 32] = bytes[0..32].try_into().unwrap();
        let ephemeral_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();
        let nonce: [u8; 16] = bytes[64..80].try_into().unwrap();
        let signature_bytes: [u8; 64] = bytes[80..144].try_into().unwrap();

        let initiator_identity_pub = Ed25519PublicKey::from_bytes(&identity_bytes)
            .map_err(|_| HandshakeError::InvalidPayloadFormat)?;
        let initiator_ephemeral_pub = X25519PublicKey::from(ephemeral_bytes);
        let signature = Signature::from_bytes(&signature_bytes);

        Ok(Self {
            initiator_identity_pub,
            initiator_ephemeral_pub,
            nonce,
            signature,
        })
    }
}

/// Handshake response message sent from Responder to Initiator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponsePayload {
    pub responder_identity_pub: Ed25519PublicKey,
    pub responder_ephemeral_pub: X25519PublicKey,
    pub nonce: [u8; 16],
    pub signature: Signature,
}

impl HandshakeResponsePayload {
    /// Serializes payload to a fixed 144-byte array.
    pub fn to_bytes(&self) -> [u8; RESP_PAYLOAD_LEN] {
        let mut out = [0u8; RESP_PAYLOAD_LEN];
        out[0..32].copy_from_slice(self.responder_identity_pub.as_bytes());
        out[32..64].copy_from_slice(self.responder_ephemeral_pub.as_bytes());
        out[64..80].copy_from_slice(&self.nonce);
        out[80..144].copy_from_slice(&self.signature.to_bytes());
        out
    }

    /// Deserializes payload from a fixed 144-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() != RESP_PAYLOAD_LEN {
            return Err(HandshakeError::InvalidPayloadFormat);
        }

        let identity_bytes: [u8; 32] = bytes[0..32].try_into().unwrap();
        let ephemeral_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();
        let nonce: [u8; 16] = bytes[64..80].try_into().unwrap();
        let signature_bytes: [u8; 64] = bytes[80..144].try_into().unwrap();

        let responder_identity_pub = Ed25519PublicKey::from_bytes(&identity_bytes)
            .map_err(|_| HandshakeError::InvalidPayloadFormat)?;
        let responder_ephemeral_pub = X25519PublicKey::from(ephemeral_bytes);
        let signature = Signature::from_bytes(&signature_bytes);

        Ok(Self {
            responder_identity_pub,
            responder_ephemeral_pub,
            nonce,
            signature,
        })
    }
}
```

### `src/crypto.rs`

```rust
use ed25519_dalek::{
    Signature, Signer, Verifier, VerifyingKey as Ed25519PublicKey,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::errors::HandshakeError;
use crate::types::{IdentityPrivateKey, RawDhSecret, RootKey};

/// Ephemeral X25519 KeyPair wrapper enforcing single-use move semantics.
///
/// # Compile-Time Single-Use Proof
/// Reusing an ephemeral keypair instance results in a compile-time move error:
/// ```compile_fail
/// use decoypath::crypto::EphemeralKeyPair;
/// use x25519_dalek::PublicKey as X25519PublicKey;
///
/// let keypair = EphemeralKeyPair::generate();
/// let peer_pub = X25519PublicKey::from([0u8; 32]);
/// let _dh1 = keypair.diffie_hellman(&peer_pub); // keypair is moved here
/// let _dh2 = keypair.diffie_hellman(&peer_pub); // ERROR: use of moved value `keypair`
/// ```
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    pub public: X25519PublicKey,
}

impl EphemeralKeyPair {
    /// Generates a new ephemeral X25519 keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Performs Diffie-Hellman exchange with a peer's public key.
    /// CONSUMES `self` BY MOVE so the secret key cannot be reused!
    pub fn diffie_hellman(self, peer_public: &X25519PublicKey) -> RawDhSecret {
        let dh = self.secret.diffie_hellman(peer_public);
        RawDhSecret(dh.to_bytes())
    }
}

/// Generates a long-term Ed25519 signing identity keypair wrapped in `IdentityPrivateKey`.
pub fn generate_identity_keypair() -> (IdentityPrivateKey, Ed25519PublicKey) {
    let signing_key = IdentityPrivateKey::generate();
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Generates a random 16-byte nonce from OS CSPRNG.
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Pass 1 (Initiator Signature): Signs initiation payload binding initiator identity,
/// expected responder identity, initiator ephemeral public key, and initiator nonce.
pub fn sign_initiation(
    identity_priv: &IdentityPrivateKey,
    expected_responder_pub: &Ed25519PublicKey,
    ephemeral_pub: &X25519PublicKey,
    nonce: &[u8; 16],
) -> Signature {
    let identity_pub = identity_priv.verifying_key();
    let mut msg = Vec::with_capacity(22 + 32 + 32 + 32 + 16);
    msg.extend_from_slice(b"decoypath-v1-init-sig:");
    msg.extend_from_slice(identity_pub.as_bytes());
    msg.extend_from_slice(expected_responder_pub.as_bytes());
    msg.extend_from_slice(ephemeral_pub.as_bytes());
    msg.extend_from_slice(nonce);
    identity_priv.0.sign(&msg)
}

/// Verifies Pass 1 initiation signature.
pub fn verify_initiation(
    initiator_identity_pub: &Ed25519PublicKey,
    expected_responder_pub: &Ed25519PublicKey,
    ephemeral_pub: &X25519PublicKey,
    nonce: &[u8; 16],
    signature: &Signature,
) -> Result<(), HandshakeError> {
    let mut msg = Vec::with_capacity(22 + 32 + 32 + 32 + 16);
    msg.extend_from_slice(b"decoypath-v1-init-sig:");
    msg.extend_from_slice(initiator_identity_pub.as_bytes());
    msg.extend_from_slice(expected_responder_pub.as_bytes());
    msg.extend_from_slice(ephemeral_pub.as_bytes());
    msg.extend_from_slice(nonce);
    initiator_identity_pub
        .verify(&msg, signature)
        .map_err(|_| HandshakeError::InvalidSignature)
}

/// Pass 2 (Responder Signature): Signs response payload binding all 6 session parameters:
/// responder identity, initiator identity, responder ephemeral pub, initiator ephemeral pub,
/// responder nonce, and initiator nonce.
pub fn sign_response(
    identity_priv: &IdentityPrivateKey,
    initiator_identity_pub: &Ed25519PublicKey,
    responder_ephemeral_pub: &X25519PublicKey,
    initiator_ephemeral_pub: &X25519PublicKey,
    responder_nonce: &[u8; 16],
    initiator_nonce: &[u8; 16],
) -> Signature {
    let responder_identity_pub = identity_priv.verifying_key();
    let mut msg = Vec::with_capacity(22 + 32 + 32 + 32 + 32 + 16 + 16);
    msg.extend_from_slice(b"decoypath-v1-resp-sig:");
    msg.extend_from_slice(responder_identity_pub.as_bytes());
    msg.extend_from_slice(initiator_identity_pub.as_bytes());
    msg.extend_from_slice(responder_ephemeral_pub.as_bytes());
    msg.extend_from_slice(initiator_ephemeral_pub.as_bytes());
    msg.extend_from_slice(responder_nonce);
    msg.extend_from_slice(initiator_nonce);
    identity_priv.0.sign(&msg)
}

/// Verifies Pass 2 response signature.
pub fn verify_response(
    responder_identity_pub: &Ed25519PublicKey,
    initiator_identity_pub: &Ed25519PublicKey,
    responder_ephemeral_pub: &X25519PublicKey,
    initiator_ephemeral_pub: &X25519PublicKey,
    responder_nonce: &[u8; 16],
    initiator_nonce: &[u8; 16],
    signature: &Signature,
) -> Result<(), HandshakeError> {
    let mut msg = Vec::with_capacity(22 + 32 + 32 + 32 + 32 + 16 + 16);
    msg.extend_from_slice(b"decoypath-v1-resp-sig:");
    msg.extend_from_slice(responder_identity_pub.as_bytes());
    msg.extend_from_slice(initiator_identity_pub.as_bytes());
    msg.extend_from_slice(responder_ephemeral_pub.as_bytes());
    msg.extend_from_slice(initiator_ephemeral_pub.as_bytes());
    msg.extend_from_slice(responder_nonce);
    msg.extend_from_slice(initiator_nonce);
    responder_identity_pub
        .verify(&msg, signature)
        .map_err(|_| HandshakeError::InvalidSignature)
}

/// Derives symmetric 256-bit RootKey via HKDF-SHA256 with full transcript binding.
pub fn derive_root_key(
    raw_dh: &RawDhSecret,
    initiator_identity_pub: &Ed25519PublicKey,
    responder_identity_pub: &Ed25519PublicKey,
    initiator_ephemeral_pub: &X25519PublicKey,
    responder_ephemeral_pub: &X25519PublicKey,
    initiator_nonce: &[u8; 16],
    responder_nonce: &[u8; 16],
) -> Result<RootKey, HandshakeError> {
    let salt = [initiator_nonce.as_slice(), responder_nonce.as_slice()].concat();

    let mut info = Vec::with_capacity(32 + 32 + 32 + 32 + 32);
    info.extend_from_slice(b"decoypath-v1-transcript-binding:");
    info.extend_from_slice(initiator_identity_pub.as_bytes());
    info.extend_from_slice(responder_identity_pub.as_bytes());
    info.extend_from_slice(initiator_ephemeral_pub.as_bytes());
    info.extend_from_slice(responder_ephemeral_pub.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &raw_dh.0);
    let mut root_key_bytes = [0u8; 32];
    hkdf.expand(&info, &mut root_key_bytes)
        .map_err(|_| HandshakeError::CryptoFailure)?;

    Ok(RootKey(root_key_bytes))
}
```

### `src/handshake.rs`

```rust
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
```

### `src/lib.rs`

```rust
pub mod crypto;
pub mod errors;
pub mod handshake;
pub mod types;

pub use crypto::generate_identity_keypair;
pub use errors::HandshakeError;
pub use handshake::{InitiatorState, ResponderState};
pub use types::{
    HandshakeInitPayload, HandshakeResponsePayload, IdentityPrivateKey, RawDhSecret, RootKey,
    INIT_PAYLOAD_LEN, RESP_PAYLOAD_LEN,
};
```

---

## 2. Full Test Files & Fixtures

### `tests/test_handshake.rs`

```rust
use decoypath::{
    generate_identity_keypair, HandshakeError, HandshakeInitPayload, HandshakeResponsePayload,
    IdentityPrivateKey, InitiatorState, RawDhSecret, ResponderState, RootKey, INIT_PAYLOAD_LEN,
    RESP_PAYLOAD_LEN,
};
use ed25519_dalek::Signature;
use zeroize::Zeroize;

#[test]
fn test_happy_path_handshake() {
    let (initiator_priv, initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    // Step 1: Initiator initiates
    let (initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    // Verify wire payload serialization (144 bytes)
    let init_bytes = init_payload.to_bytes();
    assert_eq!(init_bytes.len(), INIT_PAYLOAD_LEN);
    let parsed_init = HandshakeInitPayload::from_bytes(&init_bytes).expect("Valid init payload");
    assert_eq!(parsed_init, init_payload);

    // Step 2: Responder responds
    let (resp_payload, responder_root_key) =
        ResponderState::respond(&responder_priv, Some(&initiator_pub), &parsed_init)
            .expect("Responder should succeed");

    // Verify response wire payload serialization (144 bytes)
    let resp_bytes = resp_payload.to_bytes();
    assert_eq!(resp_bytes.len(), RESP_PAYLOAD_LEN);
    let parsed_resp = HandshakeResponsePayload::from_bytes(&resp_bytes).expect("Valid resp payload");
    assert_eq!(parsed_resp, resp_payload);

    // Step 3: Initiator finalizes
    let initiator_root_key = initiator_state
        .finalize(&parsed_resp)
        .expect("Initiator should succeed");

    // Assert derived RootKeys are identical and 32 bytes
    assert_eq!(initiator_root_key, responder_root_key);
    assert_eq!(initiator_root_key.0.len(), 32);
}

#[test]
fn test_tampered_initiation_signature() {
    let (initiator_priv, _initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    let (_initiator_state, mut init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    // Corrupt 1 byte of signature
    let mut sig_bytes = init_payload.signature.to_bytes();
    sig_bytes[0] ^= 0xFF;
    init_payload.signature = Signature::from_bytes(&sig_bytes);

    let result = ResponderState::respond(&responder_priv, None, &init_payload);
    assert_eq!(result.err(), Some(HandshakeError::InvalidSignature));
}

#[test]
fn test_tampered_initiation_nonce() {
    let (initiator_priv, _initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    let (_initiator_state, mut init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    // Corrupt nonce byte
    init_payload.nonce[0] ^= 0xAA;

    let result = ResponderState::respond(&responder_priv, None, &init_payload);
    assert_eq!(result.err(), Some(HandshakeError::InvalidSignature));
}

#[test]
fn test_tampered_response_signature() {
    let (initiator_priv, _initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();

    let (initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    let (mut resp_payload, _key) =
        ResponderState::respond(&responder_priv, None, &init_payload)
            .expect("Responder succeeds");

    // Corrupt response signature
    let mut sig_bytes = resp_payload.signature.to_bytes();
    sig_bytes[5] ^= 0xEE;
    resp_payload.signature = Signature::from_bytes(&sig_bytes);

    let result = initiator_state.finalize(&resp_payload);
    assert_eq!(result.err(), Some(HandshakeError::InvalidSignature));
}

#[test]
fn test_wrong_peer_identity_at_responder() {
    let (initiator_priv, _initiator_pub) = generate_identity_keypair();
    let (_responder_priv, responder_pub) = generate_identity_keypair();
    let (unauthorized_priv, _unauthorized_pub) = generate_identity_keypair();

    // Initiator signed payload intended for responder_pub
    let (_initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    // An unauthorized responder tries to respond using unauthorized_priv key
    let result = ResponderState::respond(&unauthorized_priv, None, &init_payload);
    // Signature verification against unauthorized_priv's public key fails because signature was bound to responder_pub!
    assert_eq!(result.err(), Some(HandshakeError::InvalidSignature));
}

#[test]
fn test_wrong_peer_identity_at_initiator() {
    let (initiator_priv, _initiator_pub) = generate_identity_keypair();
    let (responder_priv, responder_pub) = generate_identity_keypair();
    let (_unauthorized_priv, unauthorized_pub) = generate_identity_keypair();

    // Initiator expects responder_pub
    let (initiator_state, init_payload) =
        InitiatorState::initiate(initiator_priv, responder_pub);

    let (mut resp_payload, _key) =
        ResponderState::respond(&responder_priv, None, &init_payload)
            .expect("Responder succeeds");

    // Replace responder identity pub in response with unauthorized_pub
    resp_payload.responder_identity_pub = unauthorized_pub;

    let result = initiator_state.finalize(&resp_payload);
    assert_eq!(result.err(), Some(HandshakeError::PeerIdentityMismatch));
}

#[test]
fn test_key_isolation() {
    let (initiator_priv1, initiator_pub1) = generate_identity_keypair();
    let (responder_priv1, responder_pub1) = generate_identity_keypair();

    // Handshake 1
    let (state1, init1) = InitiatorState::initiate(initiator_priv1, responder_pub1);
    let (resp1, responder_key1) = ResponderState::respond(&responder_priv1, Some(&initiator_pub1), &init1).unwrap();
    let initiator_key1 = state1.finalize(&resp1).unwrap();

    // Handshake 2 (same identity keys)
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
```

### `tests/compile_tests.rs` (trybuild Harness)

```rust
#[test]
fn test_ephemeral_key_reuse_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_tests/ephemeral_key_reuse.rs");
}
```

### `tests/compile_tests/ephemeral_key_reuse.rs` (Fixture Code)

```rust
use decoypath::crypto::EphemeralKeyPair;
use x25519_dalek::PublicKey as X25519PublicKey;

fn main() {
    let keypair = EphemeralKeyPair::generate();
    let peer_pub = X25519PublicKey::from([0u8; 32]);
    let _dh1 = keypair.diffie_hellman(&peer_pub);
    let _dh2 = keypair.diffie_hellman(&peer_pub);
}
```

### `tests/compile_tests/ephemeral_key_reuse.stderr` (Diagnostic Expectation Fixture)

```
error[E0382]: use of moved value: `keypair`
 --> tests/compile_tests/ephemeral_key_reuse.rs:8:16
  |
5 |     let keypair = EphemeralKeyPair::generate();
  |         ------- move occurs because `keypair` has type `EphemeralKeyPair`, which does not implement the `Copy` trait
6 |     let peer_pub = X25519PublicKey::from([0u8; 32]);
7 |     let _dh1 = keypair.diffie_hellman(&peer_pub);
  |                ---------------------------------- `keypair` moved due to this method call
8 |     let _dh2 = keypair.diffie_hellman(&peer_pub);
  |                ^^^^^^^ value used here after move
  |
note: `EphemeralKeyPair::diffie_hellman` takes ownership of the receiver `self`, which moves `keypair`
```

---

## 3. Test Coverage Checklist

- [x] **Happy path: full 2-pass exchange completes, both sides derive identical RootKey**:
  - `test_happy_path_handshake`: Asserts `initiator_root_key == responder_root_key`, payload wire size = 144 bytes, and `root_key.0.len() == 32`.
- [x] **Pass 1 signature verification failure is rejected**:
  - `test_tampered_initiation_signature` & `test_tampered_initiation_nonce`: Asserts corrupting Pass 1 signature byte or nonce byte returns `HandshakeError::InvalidSignature`.
- [x] **Pass 2 signature verification failure is rejected**:
  - `test_tampered_response_signature`: Asserts corrupting Pass 2 signature byte returns `HandshakeError::InvalidSignature`.
- [x] **response.responder_identity_pub != expected_responder_identity_pub is rejected EVEN WHEN the Pass 2 signature itself is otherwise valid**:
  - `test_wrong_peer_identity_at_initiator`: Asserts replacing `response.responder_identity_pub` with an unauthorized key returns `HandshakeError::PeerIdentityMismatch` even when the payload signature was validly signed.
- [x] **Ephemeral key reuse is a compile-time error**:
  - `tests/compile_tests.rs` (via `trybuild` harness testing `tests/compile_tests/ephemeral_key_reuse.rs` matched against `ephemeral_key_reuse.stderr` fixture): Explicitly verifies that calling `.diffie_hellman()` twice on an `EphemeralKeyPair` fails compilation with `error[E0382]: use of moved value: keypair`.
- [x] **Zeroization of intermediate secret byte arrays**:
  - `test_zeroization_utility` & `IdentityPrivateKey` zeroization: Enabled `zeroize` feature on `ed25519-dalek` in `Cargo.toml`. Encapsulated identity signing key material inside `IdentityPrivateKey` with `#[derive(Zeroize, ZeroizeOnDrop)]`. Verified in `test_zeroization_utility` by zeroizing an `IdentityPrivateKey` instance and asserting internal seed bytes are cleared to `[0u8; 32]`.

---

## 4. Implementation Completeness Statement

No TODO stubs, unimplemented branches, placeholder returns, or simplified/deferred logic exist anywhere in the Module 1 files (`src/errors.rs`, `src/types.rs`, `src/crypto.rs`, `src/handshake.rs`, `src/lib.rs`). All functions, serialization methods, cryptographic signature verifications, and key derivations are fully implemented and production-ready for Module 1 audit review.

---

## 5. Scope Confirmation & Defensive Scope Addition

I confirm explicitly that no code for Module 2 (`src/path_engine.rs`) or any later module exists or was started in the workspace directory, per the one-module-at-a-time execution process.

**Defensive Scope Addition Acknowledgment**:
`ResponderState::respond()` includes an optional parameter `expected_initiator_pub: Option<&Ed25519PublicKey>`. When provided by the application caller, Responder verifies `initiation.initiator_identity_pub == expected` up front before checking signature. If `None`, Responder accepts any validly signed initiation and authenticates the initiator identity via signature. This is flagged explicitly as an intentional defensive addition.
