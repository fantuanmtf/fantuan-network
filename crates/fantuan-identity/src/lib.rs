//! Fantuan Network identity layer.
//!
//! Provides the OpenPGP key hierarchy, signed node descriptors, session
//! identity binding, end-to-end payload encryption, trust vouches and the
//! persistent trust graph. Implementation follows `docs/PROTOCOL.md`.

pub mod binding;
pub mod descriptor;
pub mod error;
pub mod keys;
pub mod pgp_crypto;
pub mod trust;
pub mod trust_graph;
pub mod vouch;

pub use binding::{create_binding, verify_binding};
pub use descriptor::Descriptor;
pub use error::{IdentityError, Result};
pub use keys::Identity;
pub use pgp_crypto::{decrypt, encrypt_for};
pub use trust::{PeerRecord, Relationship, TrustLevel, TrustStore};
pub use trust_graph::TrustGraph;
pub use vouch::TrustVouch;
