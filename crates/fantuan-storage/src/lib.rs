//! Fantuan Network storage layer.
//!
//! * `chunk` — split, encrypt, decrypt and assemble files;
//! * `cache` — redb chunk cache with a byte budget;
//! * `dht` — simplified Kademlia routing table;
//! * `replication` — closest-node provider selection.

pub mod cache;
pub mod chunk;
pub mod dht;
pub mod error;
pub mod replication;

pub use cache::ChunkCache;
pub use chunk::{assemble, build_chunks, decrypt_chunk};
pub use dht::{Contact, NodeId, RoutingTable, bucket_index, distance, node_id};
pub use error::{Result, StorageError};
pub use replication::{providers_for, should_store};
