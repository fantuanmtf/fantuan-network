//! Shared node state.
//!
//! One `NodeState` is shared by every connection task. It owns the identity,
//! trust store, message store, relay admission control, routing table,
//! subscriptions and the connection pool.

use crate::admission::AdmissionControl;
use crate::nonce::RelayNonce;
use crate::store::MessageStore;
use fantuan_anon::{ReputationTracker, RoundDriver};
use fantuan_core::config::NodeConfig;
use fantuan_identity::{Identity, TrustStore};
use fantuan_storage::{ChunkCache, Contact, RoutingTable, node_id};
use fantuan_transport::{ConnectionPool, DEFAULT_MAX_CONNECTIONS};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

/// Reverse path for a forwarded chunk request.
#[derive(Debug, Clone)]
pub struct PendingChunkRoute {
    /// Node that originated the request.
    pub requester: String,
    /// Peer we received the request from (next hop toward the requester).
    pub via: String,
    /// When this route expires.
    pub expires: Instant,
}

/// How long a chunk request route is remembered.
pub const CHUNK_ROUTE_TTL: Duration = Duration::from_secs(30);

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
    /// A file became available locally (manifest stored).
    FileAvailable {
        /// File id (hex).
        file_id: String,
        /// File name.
        name: String,
        /// Plaintext size.
        size: u64,
        /// Who sent the manifest.
        from: String,
    },
    /// An anonymous DC-Net message was extracted.
    Anonymous {
        /// Channel label.
        channel: String,
        /// Extracted text.
        text: String,
        /// Round id.
        round_id: u64,
    },
    /// A peer was evicted from DC-Net rounds after repeated dropouts.
    PeerEvicted {
        /// Evicted peer fingerprint.
        fingerprint: String,
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
    /// Content-addressed chunk cache.
    pub chunks: Arc<ChunkCache>,
    /// Kademlia routing table.
    pub routing: Mutex<RoutingTable>,
    /// Reverse paths for forwarded chunk requests.
    pub chunk_routes: Mutex<HashMap<[u8; 32], Vec<PendingChunkRoute>>>,
    /// DC-Net round state machine.
    pub rounds: Mutex<RoundDriver>,
    /// DC-Net dropout reputation.
    pub reputation: Mutex<ReputationTracker>,
    seen_requests: Mutex<HashMap<([u8; 32], String), Instant>>,
    event_stream: broadcast::Sender<NodeEvent>,
    relay_nonce: RelayNonce,
}

impl NodeState {
    /// Create shared state for one node.
    ///
    /// `relay_nonce_path` is the durable reservation file for outbound relay
    /// nonces; `None` keeps the counter in memory (tests, ephemeral nodes).
    pub fn new(
        identity: Arc<Identity>,
        config: NodeConfig,
        trust: TrustStore,
        messages: MessageStore,
        chunks: ChunkCache,
        events: mpsc::UnboundedSender<NodeEvent>,
        relay_nonce_path: Option<PathBuf>,
    ) -> Arc<Self> {
        let subscriptions = Subscriptions {
            channels: config.channels.iter().cloned().collect(),
            boards: config.boards.iter().cloned().collect(),
        };
        let local_id = node_id(&identity.fingerprint_hex());
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
            chunks: Arc::new(chunks),
            routing: Mutex::new(RoutingTable::new(local_id, 20)),
            chunk_routes: Mutex::new(HashMap::new()),
            rounds: Mutex::new(RoundDriver::new()),
            reputation: Mutex::new(ReputationTracker::new()),
            seen_requests: Mutex::new(HashMap::new()),
            event_stream,
            relay_nonce: RelayNonce::load(relay_nonce_path),
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
    ///
    /// Strictly increasing across restarts; see [`crate::nonce`].
    pub fn next_relay_nonce(&self) -> u64 {
        self.relay_nonce.next()
    }

    /// Record a peer in the Kademlia routing table.
    pub fn observe_peer(&self, fingerprint: &str) {
        let contact = Contact {
            id: node_id(fingerprint),
            fingerprint: fingerprint.to_string(),
        };
        if let Ok(mut routing) = self.routing.lock() {
            routing.insert(contact);
        }
    }

    /// Connected peers whose node id is closest to `target`.
    pub fn closest_peers(&self, target: &[u8; 32], count: usize) -> Vec<String> {
        let Ok(routing) = self.routing.lock() else {
            return Vec::new();
        };
        routing
            .closest(target, count)
            .into_iter()
            .map(|contact| contact.fingerprint)
            .filter(|fingerprint| self.pool.is_connected(fingerprint))
            .collect()
    }

    /// Remember the reverse path for a forwarded chunk request.
    pub fn remember_chunk_route(&self, hash: &[u8; 32], requester: &str, via: &str) {
        if let Ok(mut routes) = self.chunk_routes.lock() {
            let entries = routes.entry(*hash).or_default();
            entries.retain(|route| route.expires > Instant::now());
            if entries.len() < 16 {
                entries.push(PendingChunkRoute {
                    requester: requester.to_string(),
                    via: via.to_string(),
                    expires: Instant::now() + CHUNK_ROUTE_TTL,
                });
            }
        }
    }

    /// Take (and clear) unexpired reverse paths for a chunk hash.
    pub fn take_chunk_routes(&self, hash: &[u8; 32]) -> Vec<PendingChunkRoute> {
        let Ok(mut routes) = self.chunk_routes.lock() else {
            return Vec::new();
        };
        let mut entries = routes.remove(hash).unwrap_or_default();
        entries.retain(|route| route.expires > Instant::now());
        entries
    }

    /// True when this `(hash, requester)` request was already seen recently.
    pub fn seen_request(&self, hash: &[u8; 32], requester: &str) -> bool {
        let Ok(mut seen) = self.seen_requests.lock() else {
            return false;
        };
        seen.retain(|_, recorded| recorded.elapsed() < CHUNK_ROUTE_TTL);
        if seen.contains_key(&(*hash, requester.to_string())) {
            return true;
        }
        if seen.len() >= 4096 {
            seen.clear();
        }
        seen.insert((*hash, requester.to_string()), Instant::now());
        false
    }
}
