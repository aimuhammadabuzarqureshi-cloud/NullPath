use std::collections::BTreeMap;

use crate::anti_replay::AntiReplayStore;
use crate::decoy::generate_multi_path_slots;
use crate::envelope::{open, seal, ENVELOPE_TOTAL_LEN};
use crate::errors::ChannelError;
use crate::path_engine::{select_slot, RatchetKey};
use crate::types::RootKey;

/// Maximum allowed sequence number skip window (1000 messages).
pub const MAX_SKIP_WINDOW: usize = 1000;

/// Maximum capacity limit for skipped_keys table (1000 entries).
pub const MAX_SKIPPED_KEYS: usize = 1000;

/// Maximum allowed byte length for message_id (256 bytes).
pub const MAX_MESSAGE_ID_LEN: usize = 256;

/// Top-level secure channel managing stateful multi-path message exchange and anti-replay defense.
///
/// # DoS & CPU Cost Boundary
/// Bounding sequence forward ratcheting to `MAX_SKIP_WINDOW = 1000` caps the maximum derivation work per
/// unauthenticated packet to 1,000 SHA-256 steps (~0.1ms). Remote network callers attempting repeated
/// high-skip forged packets can still induce bounded CPU computation prior to AEAD rejection in Step 3;
/// application callers operating over untrusted networks are advised to apply rate-limiting per peer address.
pub struct SecureChannel {
    last_seq: Option<u64>,
    send_seq: Option<u64>,
    current_key: RatchetKey,
    skipped_keys: BTreeMap<u64, RatchetKey>,
    anti_replay: AntiReplayStore,
    n_paths: usize,
}

impl SecureChannel {
    /// Initializes a new SecureChannel from a shared 256-bit RootKey and path count.
    pub fn new(root_key: RootKey, n_paths: usize) -> Self {
        Self {
            last_seq: None,
            send_seq: None,
            current_key: RatchetKey::new(root_key.0),
            skipped_keys: BTreeMap::new(),
            anti_replay: AntiReplayStore::new(),
            n_paths,
        }
    }

    /// Helper to construct AAD payload binding sequence number and message ID:
    /// `b"decoypath-v1-msg-aad:" || seq.to_be_bytes() || message_id`.
    fn construct_aad(seq: u64, message_id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(21 + 8 + message_id.len());
        aad.extend_from_slice(b"decoypath-v1-msg-aad:");
        aad.extend_from_slice(&seq.to_be_bytes());
        aad.extend_from_slice(message_id);
        aad
    }

    /// Evicts oldest skipped keys in O(log N) time when `skipped_keys` capacity exceeds `MAX_SKIPPED_KEYS`.
    fn evict_oldest_skipped_keys(&mut self) {
        while self.skipped_keys.len() > MAX_SKIPPED_KEYS {
            // pop_first() pops min_seq key by move, dropping & zeroizing the RatchetKey
            if self.skipped_keys.pop_first().is_none() {
                break;
            }
        }
    }

    /// Encrypts and distributes a message payload across `n_paths` multi-path envelope slots.
    pub fn send(
        &mut self,
        payload: &[u8],
        message_id: &[u8],
    ) -> Result<Vec<[u8; ENVELOPE_TOTAL_LEN]>, ChannelError> {
        if message_id.len() > MAX_MESSAGE_ID_LEN {
            return Err(ChannelError::InvalidMessageId);
        }

        let seq = match self.send_seq {
            None => 0,
            Some(s) => s + 1,
        };

        let valid_slot = select_slot(&self.current_key.0, message_id, self.n_paths)
            .map_err(|_| ChannelError::DecoyFailure)?;

        let aad = Self::construct_aad(seq, message_id);

        let real_envelope = seal(&self.current_key.0, payload, &aad)
            .map_err(|_| ChannelError::AuthenticationFailed)?;

        // Advance sender ratchet key
        self.current_key = self.current_key.derive_next();
        self.send_seq = Some(seq);

        generate_multi_path_slots(real_envelope, valid_slot, self.n_paths, &aad)
            .map_err(|_| ChannelError::DecoyFailure)
    }

    /// Receives, authenticates, and decrypts a multi-path envelope set using a 5-step transactional pipeline.
    pub fn receive(
        &mut self,
        envelopes: &[[u8; ENVELOPE_TOTAL_LEN]],
        seq: u64,
        message_id: &[u8],
    ) -> Result<Vec<u8>, ChannelError> {
        if message_id.len() > MAX_MESSAGE_ID_LEN {
            return Err(ChannelError::InvalidMessageId);
        }
        if envelopes.len() < self.n_paths {
            return Err(ChannelError::DecoyFailure);
        }

        // =========================================================================
        // STEP 1: Compute / Borrow target_key (READ-ONLY FOR OUT-OF-ORDER LOOKUPS)
        // =========================================================================
        let mut local_skipped = BTreeMap::new();
        let target_key: RatchetKey;
        let next_ratchet_key: Option<RatchetKey>;
        let is_forward: bool;

        match self.last_seq {
            None => {
                if seq == 0 {
                    // Bootstrap Case: seq == 0, first message ever processed
                    is_forward = true;
                    target_key = self.current_key.duplicate_for_target_use();
                    next_ratchet_key = Some(self.current_key.derive_next());
                } else {
                    // seq > 0 before any message processed
                    if seq > MAX_SKIP_WINDOW as u64 {
                        return Err(ChannelError::InvalidSequence);
                    }
                    is_forward = true;
                    let mut runner = self.current_key.duplicate_for_target_use();
                    for s in 0..seq {
                        local_skipped.insert(s, runner.duplicate_for_target_use());
                        runner = runner.derive_next();
                    }
                    target_key = runner.duplicate_for_target_use();
                    next_ratchet_key = Some(runner.derive_next());
                }
            }
            Some(last) => {
                if seq > last {
                    // Forward arrival
                    let skip_count = seq - last;
                    if skip_count > MAX_SKIP_WINDOW as u64 {
                        return Err(ChannelError::InvalidSequence);
                    }
                    is_forward = true;
                    let mut runner = self.current_key.duplicate_for_target_use();
                    for s in (last + 1)..seq {
                        local_skipped.insert(s, runner.duplicate_for_target_use());
                        runner = runner.derive_next();
                    }
                    target_key = runner.duplicate_for_target_use();
                    next_ratchet_key = Some(runner.derive_next());
                } else {
                    // Out-of-order arrival (seq <= last)
                    // STRICTLY READ-ONLY BORROW: .get(&seq) + duplicate_for_target_use()
                    let key_ref = match self.skipped_keys.get(&seq) {
                        Some(k) => k,
                        None => {
                            if self.anti_replay.contains(seq, message_id) {
                                return Err(ChannelError::ReplayedSequence);
                            } else {
                                return Err(ChannelError::SkippedKeyExpired);
                            }
                        }
                    };
                    is_forward = false;
                    target_key = key_ref.duplicate_for_target_use();
                    next_ratchet_key = None;
                    // Note: self.skipped_keys is NOT mutated in Step 1!
                }
            }
        }

        // =========================================================================
        // STEP 2: Select Slot Index
        // =========================================================================
        let slot_idx = select_slot(&target_key.0, message_id, self.n_paths)
            .map_err(|_| ChannelError::DecoyFailure)?;

        if slot_idx >= envelopes.len() {
            return Err(ChannelError::DecoyFailure);
        }

        // =========================================================================
        // STEP 3: AEAD Decryption & Tag Authentication
        // =========================================================================
        let aad = Self::construct_aad(seq, message_id);

        let payload = open(&target_key.0, &envelopes[slot_idx], &aad).map_err(|_| {
            // Target key drops & zeroizes here; state remains 100% zero-mutated!
            ChannelError::AuthenticationFailed
        })?;

        // =========================================================================
        // STEP 4: Anti-Replay Insertion
        // =========================================================================
        if !self.anti_replay.check_and_insert(seq, message_id) {
            // Target key drops & zeroizes here; state remains 100% zero-mutated!
            return Err(ChannelError::ReplayedSequence);
        }

        // =========================================================================
        // STEP 5: Atomic State Commit (ONLY AFTER STEPS 1-4 SUCCEED)
        // =========================================================================
        if is_forward {
            // Branch A (Forward: seq > last or last_seq == None)
            for (s, k) in local_skipped {
                self.skipped_keys.insert(s, k);
            }
            self.evict_oldest_skipped_keys();
            self.last_seq = Some(seq);
            self.current_key = next_ratchet_key.unwrap();
        } else {
            // Branch B (Out-of-Order: seq <= last)
            // Removes consumed key by move and zeroizes it; leaves last_seq & current_key UNTOUCHED
            self.skipped_keys.remove(&seq);
        }

        Ok(payload)
    }

    /// Returns the highest successfully authenticated sequence number.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }
}
