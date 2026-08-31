//! In-Flight Request Coalescer (P0 - Thundering Herd Protection)
//!
//! Deduplicates identical concurrent requests within the same cache window.
//! When duplicate prompts arrive simultaneously, exactly one request is sent to the provider
//! while other callers subscribe to the leader's broadcast channel.

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::broadcast;

#[derive(Clone, Debug)]
pub struct CoalescedResponse {
    pub body: Bytes,
    pub content_type: String,
    pub status: u16,
}

pub enum CoalesceAction {
    /// This caller is the first to arrive; it must make the upstream call and broadcast the result.
    Leader(broadcast::Sender<Result<CoalescedResponse, String>>),
    /// Another caller is already making the upstream call; wait for its broadcast.
    Follower(broadcast::Receiver<Result<CoalescedResponse, String>>),
}

pub struct RequestCoalescer {
    in_flight: DashMap<[u8; 32], broadcast::Sender<Result<CoalescedResponse, String>>>,
}

impl Default for RequestCoalescer {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestCoalescer {
    pub fn new() -> Self {
        Self {
            in_flight: DashMap::new(),
        }
    }

    /// Try to join an in-flight request or become the leader.
    pub fn join_or_lead(&self, key: [u8; 32]) -> CoalesceAction {
        // Check if there's already an active broadcast channel
        if let Some(sender) = self.in_flight.get(&key) {
            let rx = sender.subscribe();
            return CoalesceAction::Follower(rx);
        }

        // Otherwise, become the leader
        let (tx, _rx) = broadcast::channel(16);
        self.in_flight.insert(key, tx.clone());
        CoalesceAction::Leader(tx)
    }

    /// Called by the leader to notify all waiters and clean up the in-flight entry.
    pub fn complete(&self, key: &[u8; 32], result: Result<CoalescedResponse, String>) {
        if let Some((_, sender)) = self.in_flight.remove(key) {
            let _ = sender.send(result);
        }
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }
}
