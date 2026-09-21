//! Fantuan Network identity layer.
//!
//! Provides the OpenPGP key hierarchy, the signed node descriptor and the
//! persistent trust graph. Implementation follows `docs/PROTOCOL.md`.

pub mod binding;
pub mod descriptor;
pub mod error;
pub mod keys;
pub mod trust;

pub use binding::{create_binding, verify_binding};

pub use descriptor::Descriptor;
pub use error::{IdentityError, Result};
pub use keys::Identity;
pub use trust::{PeerRecord, Relationship, TrustStore};
