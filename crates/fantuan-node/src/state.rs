//! Shared node state.
//!
//! One `NodeState` is shared by every connection task. It owns the identity,
//! trust store, message store, relay admission control, routing table,
//! subscriptions and the connection pool.

use crate::admission::AdmissionControl;
use crate::store::MessageStore;
use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_transport::{ConnectionPool, DEFAULT_MAX_CONNECTIONS};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

/// Events surfaced to the local operator.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum NodeEvent {
    /// A signed direct message was delivered to us.
    Message {
        /// Sender fingerprint.
        from: String,
        /// Message text.
        text: String,
    },
    /// A relay envelope addressed to us was decrypted.
    Relay {
        /// Origin fingerprint.
        from: String,
    },
    /// A channel message was stored.
    Channel {
        /// Channel name.
        channel: String,
        /// Sender fingerprint.
        from: String,
        /// Message text.
        text: String,
        /// Unix seconds.
        timestamp: u64,
    },
    /// A forum post was stored.
    Forum {
        /// Board name.
        board: String,
        /// Sender fingerprint.
        from: String,
        /// Post title.
        title: String,
        /// Post body.
        body: String,
        /// Unix seconds.
        timestamp: u64,
    },
}

/// Topic subscriptions.
#[derive(Debug, Default)]
pub struct Subscriptions {
    /// Channels we store and serve.
    pub channels: HashSet<String>,
    /// Boards we store and serve.
    pub boards: HashSet<String>,
}

/// Shared runtime state.
pub struct NodeState {
    /// Node identity.
    pub identity: Arc<Identity>,
    /// Node configuration.
    pub config: NodeConfig,
    /// Trust graph storage.
    pub trust: Mutex<TrustStore>,
    /// Local message store.
    pub messages: Mutex<MessageStore>,
    /// Relay admission control.
    pub admissions: Mutex<AdmissionControl>,
    /// Destination fingerprint → next-hop fingerprint.
    pub routes: Mutex<HashMap<String, String>>,
    /// Channel and board subscriptions.
    pub subscriptions: Mutex<Subscriptions>,
    /// Active connections.
    pub pool: ConnectionPool,
    /// Console event sink.
    pub events: mpsc::UnboundedSender<NodeEvent>,
    event_stream: broadcast::Sender<NodeEvent>,
    relay_nonce: AtomicU64,
}

impl NodeState {
    /// Create shared state for one node.
    pub fn new(
        identity: Arc<Identity>,
        config: NodeConfig,
        trust: TrustStore,
        messages: MessageStore,
        events: mpsc::UnboundedSender<NodeEvent>,
    ) -> Arc<Self> {
        let subscriptions = Subscriptions {
            channels: config.channels.iter().cloned().collect(),
            boards: config.boards.iter().cloned().collect(),
        };
        let (event_stream, _) = broadcast::channel(1024);
        Arc::new(Self {
            identity,
            config,
            trust: Mutex::new(trust),
            messages: Mutex::new(messages),
            admissions: Mutex::new(AdmissionControl::new()),
            routes: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(subscriptions),
            pool: ConnectionPool::new(DEFAULT_MAX_CONNECTIONS),
            events,
            event_stream,
            relay_nonce: AtomicU64::new(0),
        })
    }

    /// Our own fingerprint.
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint_hex()
    }

    /// Subscribe to a channel.
    pub fn subscribe_channel(&self, channel: &str) {
        if let Ok(mut subscriptions) = self.subscriptions.lock() {
            subscriptions.channels.insert(channel.to_string());
        }
    }

    /// Subscribe to a board.
    pub fn subscribe_board(&self, board: &str) {
        if let Ok(mut subscriptions) = self.subscriptions.lock() {
            subscriptions.boards.insert(board.to_string());
        }
    }

    /// True when the channel is subscribed.
    pub fn is_subscribed_channel(&self, channel: &str) -> bool {
        self.subscriptions
            .lock()
            .map(|subscriptions| subscriptions.channels.contains(channel))
            .unwrap_or(false)
    }

    /// True when the board is subscribed.
    pub fn is_subscribed_board(&self, board: &str) -> bool {
        self.subscriptions
            .lock()
            .map(|subscriptions| subscriptions.boards.contains(board))
            .unwrap_or(false)
    }

    /// All subscriptions as `(topic, is_board)`.
    pub fn subscription_list(&self) -> Vec<(String, bool)> {
        let Ok(subscriptions) = self.subscriptions.lock() else {
            return Vec::new();
        };
        let mut list: Vec<(String, bool)> = subscriptions
            .channels
            .iter()
            .map(|channel| (channel.clone(), false))
            .collect();
        list.extend(
            subscriptions
                .boards
                .iter()
                .map(|board| (board.clone(), true)),
        );
        list.sort();
        list
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

    /// Subscribe to the event stream (control socket, IRC bridge, tests).
    pub fn subscribe_events(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_stream.subscribe()
    }

    /// Send an event to local consumers.
    pub fn emit(&self, event: NodeEvent) {
        let _ = self.events.send(event.clone());
        let _ = self.event_stream.send(event);
    }

    /// Forward raw object bytes to every connected peer except `exclude`.
    pub fn flood(&self, exclude: Option<&str>, bytes: Vec<u8>) {
        for peer in self.pool.peers() {
            if Some(peer.as_str()) != exclude {
                let _ = self.pool.try_send(&peer, bytes.clone());
            }
        }
    }

    /// Next relay nonce for envelopes we originate.
    pub fn next_relay_nonce(&self) -> u64 {
        self.relay_nonce.fetch_add(1, Ordering::Relaxed) + 1
    }
}
