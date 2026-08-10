use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Capacity of the AntiReplayStore (10,000 sequence numbers).
pub const ANTI_REPLAY_CAPACITY: usize = 10_000;

/// Sliding time window for tracking sequence numbers (300 seconds = 5 minutes).
pub const ANTI_REPLAY_TIME_WINDOW: Duration = Duration::from_secs(300);

/// Structure tracking processed sequence numbers and message IDs to reject duplicate packets.
#[derive(Debug)]
pub struct AntiReplayStore {
    entries: HashMap<(u64, Vec<u8>), Instant>,
    queue: VecDeque<((u64, Vec<u8>), Instant)>,
    capacity: usize,
    time_window: Duration,
}

impl AntiReplayStore {
    /// Creates a new `AntiReplayStore` with default capacity (10,000) and window (300s).
    pub fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(ANTI_REPLAY_CAPACITY),
            queue: VecDeque::with_capacity(ANTI_REPLAY_CAPACITY),
            capacity: ANTI_REPLAY_CAPACITY,
            time_window: ANTI_REPLAY_TIME_WINDOW,
        }
    }

    /// Creates a new `AntiReplayStore` with custom capacity and time window in seconds (for testing).
    pub fn with_capacity_and_window(capacity: usize, window_secs: u64) -> Self {
        let time_window = Duration::from_secs(window_secs);
        Self {
            entries: HashMap::with_capacity(capacity),
            queue: VecDeque::with_capacity(capacity),
            capacity,
            time_window,
        }
    }

    /// Read-only check returning true if sequence number + message ID has already been recorded.
    pub fn contains(&self, seq: u64, message_id: &[u8]) -> bool {
        let key = (seq, message_id.to_vec());
        self.entries.contains_key(&key)
    }

    /// Checks if a sequence number + message ID key has been seen, inserting it if fresh.
    /// Returns `true` if inserted (fresh sequence), or `false` if replayed/duplicate.
    pub fn check_and_insert(&mut self, seq: u64, message_id: &[u8]) -> bool {
        let now = Instant::now();
        self.prune(now);

        let key = (seq, message_id.to_vec());

        if self.entries.contains_key(&key) {
            return false;
        }

        if self.entries.len() >= self.capacity {
            self.evict_oldest();
        }

        self.entries.insert(key.clone(), now);
        self.queue.push_back((key, now));
        true
    }

    /// Prunes expired entries from queue head in O(1) amortized time.
    fn prune(&mut self, now: Instant) {
        let window = self.time_window;
        while let Some(((_key, timestamp), _)) = self.queue.front().map(|e| (e, ())) {
            if now.duration_since(*timestamp) > window {
                if let Some((old_key, _)) = self.queue.pop_front() {
                    self.entries.remove(&old_key);
                }
            } else {
                break;
            }
        }
    }

    /// Evicts the single oldest entry when capacity is exceeded.
    fn evict_oldest(&mut self) {
        while let Some((oldest_key, _)) = self.queue.pop_front() {
            if self.entries.remove(&oldest_key).is_some() {
                break;
            }
        }
    }

    /// Returns current count of tracked entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if store contains no tracked entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AntiReplayStore {
    fn default() -> Self {
        Self::new()
    }
}
