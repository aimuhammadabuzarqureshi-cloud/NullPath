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
pub struct IdentityPrivateKey(pub Ed25519PrivateKey);

impl IdentityPrivateKey {
    /// Constructs IdentityPrivateKey from 32 raw key bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Ed25519PrivateKey::from_bytes(&bytes))
    }

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

impl Zeroize for IdentityPrivateKey {
    fn zeroize(&mut self) {
        self.0 = Ed25519PrivateKey::from_bytes(&[0u8; 32]);
    }
}

impl Drop for IdentityPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
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
