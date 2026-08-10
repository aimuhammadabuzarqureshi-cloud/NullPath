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
