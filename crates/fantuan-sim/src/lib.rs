//! Offline discrete-event simulator for anonymity analysis.
//!
//! The simulator produces deterministic transcripts (given a seed) that the
//! Python analyzer in `analysis/` turns into English reports. It never
//! touches the network.

pub mod attacks;
pub mod clock;
pub mod error;
pub mod metrics;
pub mod rng;
pub mod scenario;
pub mod transcript;

pub use attacks::{AttackReport, analyze};
pub use clock::{EventQueue, LogicalTime, VirtualClock};
pub use error::{Result, SimError};
pub use rng::DeterministicRng;
pub use scenario::{
    ATTACK_SELECTIVE, CALIBRATION_TIMED, CALIBRATION_UNIFORM, DCNET_COVER, DCNET_MESH, Simulation,
    run,
};
pub use transcript::{Observation, Transcript};
