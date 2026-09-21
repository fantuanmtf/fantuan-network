//! Shared node state.
//!
//! One `NodeState` is shared by every connection task. It owns the identity,
//! the trust store, relay admission control, the routing table and the
//! connection pool.

use crate::admission::AdmissionControl;
use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_transport::{ConnectionPool, DEFAULT_MAX_CONNECTIONS};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Events surfaced to the local operator.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A signed message was delivered to us.
    Message {
        /// Sender fingerprint.
        from: String,
        /// Message text.
        text: String,
    },
    /// A relay envelope addressed to us was decrypted.
    Received {
        /// Origin fingerprint.
        from: String,
    },
}

/// Shared runtime state.
pub struct NodeState {
    /// Node identity.
    pub identity: Arc<Identity>,
    /// Node configuration.
    pub config: NodeConfig,
    /// Trust graph storage.
    pub trust: Mutex<TrustStore>,
    /// Relay admission control.
    pub admissions: Mutex<AdmissionControl>,
    /// Destination fingerprint → next-hop fingerprint.
    pub routes: Mutex<HashMap<String, String>>,
    /// Active connections.
    pub pool: ConnectionPool,
    /// Event sink.
    pub events: mpsc::UnboundedSender<NodeEvent>,
    relay_nonce: AtomicU64,
}

impl NodeState {
    /// Create shared state for one node.
    pub fn new(
        identity: Arc<Identity>,
        config: NodeConfig,
        trust: TrustStore,
        events: mpsc::UnboundedSender<NodeEvent>,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity,
            config,
            trust: Mutex::new(trust),
            admissions: Mutex::new(AdmissionControl::new()),
            routes: Mutex::new(HashMap::new()),
            pool: ConnectionPool::new(DEFAULT_MAX_CONNECTIONS),
            events,
            relay_nonce: AtomicU64::new(0),
        })
    }

    /// Our own fingerprint.
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint_hex()
    }

    /// Remember that `destination` is reachable through `via`.
    pub fn record_route(&self, destination: &str, via: &str) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.insert(destination.to_string(), via.to_string());
        }
    }

    /// Resolve the next hop toward `destination`.
    ///
    /// Direct connections win over gossip-learned routes.
    pub fn next_hop(&self, destination: &str) -> Option<String> {
        if destination == self.fingerprint() {
            return None;
        }
        if self.pool.is_connected(destination) {
            return Some(destination.to_string());
        }
        self.routes
            .lock()
            .ok()
            .and_then(|routes| routes.get(destination).cloned())
    }

    /// Number of known routes.
    pub fn route_count(&self) -> usize {
        self.routes.lock().map(|routes| routes.len()).unwrap_or(0)
    }

    /// Send an event to the local operator (best effort).
    pub fn emit(&self, event: NodeEvent) {
        let _ = self.events.send(event);
    }

    /// Next relay nonce for envelopes we originate.
    pub fn next_relay_nonce(&self) -> u64 {
        self.relay_nonce.fetch_add(1, Ordering::Relaxed) + 1
    }
}
