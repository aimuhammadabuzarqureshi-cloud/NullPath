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

/// Errors that can occur within the path selection engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEngineError {
    /// Number of paths specified was zero.
    InvalidPathCount,
    /// Internal HMAC computation failure.
    HmacFailure,
}

impl fmt::Display for PathEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPathCount => write!(f, "Number of paths must be greater than zero"),
            Self::HmacFailure => write!(f, "HMAC-SHA256 path evaluation failed"),
        }
    }
}

impl std::error::Error for PathEngineError {}

/// Errors that can occur during message envelope sealing and opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Payload exceeds maximum capacity (992 bytes).
    PayloadTooLarge,
    /// AEAD encryption failure.
    EncryptionFailure,
    /// AEAD decryption or authentication tag verification failed.
    DecryptionFailure,
    /// Decrypted envelope format or version was invalid.
    InvalidFormat,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "Payload exceeds maximum 992-byte capacity"),
            Self::EncryptionFailure => write!(f, "AEAD encryption failed"),
            Self::DecryptionFailure => write!(f, "AEAD decryption or tag verification failed"),
            Self::InvalidFormat => write!(f, "Invalid decrypted envelope format or version"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Errors that can occur during decoy envelope generation and multi-path slot distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyError {
    /// Specified path count was zero.
    InvalidPathCount,
    /// Valid slot index was out of bounds for the path count.
    InvalidSlotIndex,
    /// Internal envelope sealing failure during decoy generation.
    SealFailure,
}

impl fmt::Display for DecoyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPathCount => write!(f, "Path count must be greater than zero"),
            Self::InvalidSlotIndex => write!(f, "Valid slot index is out of bounds for path count"),
            Self::SealFailure => write!(f, "Decoy envelope sealing failed"),
        }
    }
}

impl std::error::Error for DecoyError {}

/// Errors that can occur during secure channel message exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// Handshake required before secure channel operation.
    HandshakeRequired,
    /// Sequence number was replayed or already consumed.
    ReplayedSequence,
    /// Skipped ratchet key was evicted from memory due to capacity limits.
    SkippedKeyExpired,
    /// Sequence number exceeded maximum allowed skip window.
    InvalidSequence,
    /// Message ID exceeds maximum 256-byte capacity limit.
    InvalidMessageId,
    /// Sequence number or timestamp was outside time window.
    OutofWindow,
    /// AEAD authentication or decryption failed.
    AuthenticationFailed,
    /// Decoy operation or envelope failure.
    DecoyFailure,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeRequired => write!(f, "Handshake completion required"),
            Self::ReplayedSequence => write!(f, "Replayed or already consumed sequence number"),
            Self::SkippedKeyExpired => write!(f, "Skipped ratchet key was evicted from memory"),
            Self::InvalidSequence => write!(f, "Sequence number exceeds max skip window"),
            Self::InvalidMessageId => write!(f, "Message ID exceeds maximum 256-byte capacity"),
            Self::OutofWindow => write!(f, "Message outside allowed time window"),
            Self::AuthenticationFailed => write!(f, "Message authentication failed"),
            Self::DecoyFailure => write!(f, "Decoy channel processing error"),
        }
    }
}

impl std::error::Error for ChannelError {}
