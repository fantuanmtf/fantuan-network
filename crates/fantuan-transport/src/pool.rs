//! Bounded per-peer connection registry.
//!
//! Each established connection owns a writer queue. The pool stores the
//! sender half keyed by peer id plus a unique connection id, so a stale
//! cleanup can never remove a newer connection that reuses the same peer id.

use crate::error::{Result, TransportError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Default maximum number of simultaneous connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// Default capacity of one peer's writer queue.
pub const DEFAULT_WRITER_QUEUE: usize = 64;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a process-unique connection id.
pub fn next_connection_id() -> u64 {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}

/// Sender half handed to writers of one connection.
#[derive(Clone)]
pub struct ConnectionHandle {
    /// Queue of plaintext frames waiting to be encrypted and written.
    pub tx: mpsc::Sender<Vec<u8>>,
    /// Unique id of this connection.
    pub connection_id: u64,
}

/// Registry of active connections.
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, ConnectionHandle>>>,
    max_connections: usize,
}

impl ConnectionPool {
    /// Create an empty pool.
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_connections,
        }
    }

    /// Register a new connection for `peer`, creating its writer queue.
    ///
    /// Returns the handle and the receiver the connection task must drain.
    pub fn register(
        &self,
        peer: &str,
        queue_capacity: usize,
    ) -> Result<(ConnectionHandle, mpsc::Receiver<Vec<u8>>)> {
        if queue_capacity == 0 {
            return Err(TransportError::Session(
                "writer queue capacity must be positive".to_string(),
            ));
        }
        let mut connections = self
            .connections
            .lock()
            .map_err(|_| TransportError::Session("connection pool poisoned".to_string()))?;
        if connections.len() >= self.max_connections && !connections.contains_key(peer) {
            return Err(TransportError::Session(format!(
                "connection limit reached ({})",
                self.max_connections
            )));
        }
        let (tx, rx) = mpsc::channel(queue_capacity);
        let handle = ConnectionHandle {
            tx,
            connection_id: next_connection_id(),
        };
        connections.insert(peer.to_string(), handle.clone());
        Ok((handle, rx))
    }

    /// Remove a connection only when the id still matches.
    pub fn remove(&self, peer: &str, connection_id: u64) {
        if let Ok(mut connections) = self.connections.lock() {
            let stale = connections
                .get(peer)
                .map(|handle| handle.connection_id == connection_id)
                .unwrap_or(false);
            if stale {
                connections.remove(peer);
                tracing::info!(peer, connection_id, "connection removed");
            }
        }
    }

    /// True when a connection for `peer` is registered.
    pub fn is_connected(&self, peer: &str) -> bool {
        self.connections
            .lock()
            .map(|connections| connections.contains_key(peer))
            .unwrap_or(false)
    }

    /// Number of registered connections.
    pub fn count(&self) -> usize {
        self.connections
            .lock()
            .map(|connections| connections.len())
            .unwrap_or(0)
    }

    /// Connected peer ids.
    pub fn peers(&self) -> Vec<String> {
        self.connections
            .lock()
            .map(|connections| connections.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Queue a payload for `peer`, failing fast when the queue is full.
    pub fn try_send(&self, peer: &str, payload: Vec<u8>) -> Result<()> {
        let handle = {
            let connections = self
                .connections
                .lock()
                .map_err(|_| TransportError::Session("connection pool poisoned".to_string()))?;
            connections.get(peer).cloned()
        };
        let handle = handle
            .ok_or_else(|| TransportError::Session(format!("no active connection to {peer}")))?;
        handle.tx.try_send(payload).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                TransportError::Session(format!("writer queue full for {peer}"))
            }
            mpsc::error::TrySendError::Closed(_) => {
                TransportError::Session(format!("connection to {peer} is closed"))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_send() {
        let pool = ConnectionPool::new(4);
        let (handle, mut rx) = pool.register("alice", 2).expect("register");
        assert!(pool.is_connected("alice"));
        assert_eq!(pool.count(), 1);
        assert!(handle.connection_id > 0);

        pool.try_send("alice", b"one".to_vec()).expect("send");
        assert_eq!(rx.try_recv().expect("receive"), b"one");
    }

    #[test]
    fn send_without_connection_fails() {
        let pool = ConnectionPool::new(4);
        assert!(pool.try_send("nobody", vec![1]).is_err());
    }

    #[test]
    fn queue_full_fails_fast() {
        let pool = ConnectionPool::new(4);
        let (_handle, _rx) = pool.register("bob", 1).expect("register");
        pool.try_send("bob", vec![1]).expect("first");
        assert!(pool.try_send("bob", vec![2]).is_err());
    }

    #[test]
    fn connection_limit_is_enforced() {
        let pool = ConnectionPool::new(1);
        let (_handle, _rx) = pool.register("alice", 1).expect("first");
        assert!(pool.register("bob", 1).is_err());
        // Re-registering the same peer is allowed (reconnect).
        assert!(pool.register("alice", 1).is_ok());
    }

    #[test]
    fn stale_remove_keeps_newer_connection() {
        let pool = ConnectionPool::new(4);
        let (old, _old_rx) = pool.register("carol", 1).expect("old");
        let (new, _new_rx) = pool.register("carol", 1).expect("new");

        pool.remove("carol", old.connection_id);
        assert!(
            pool.is_connected("carol"),
            "stale remove must not drop the newer connection"
        );

        pool.remove("carol", new.connection_id);
        assert!(!pool.is_connected("carol"));
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let pool = ConnectionPool::new(4);
        assert!(pool.register("dave", 0).is_err());
    }
}
