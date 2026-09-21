//! Simulation core and calibration scenarios.
//!
//! The `Simulation` type is the discrete-event engine: scenarios schedule
//! observations on the virtual clock and the engine replays them in time
//! order into a `Transcript`.
//!
//! The scenarios shipped here are **calibration** scenarios. They exercise
//! the metric pipeline (entropy, variance, Pearson, mutual information) and
//! do not model or claim any protocol-level anonymity property; protocol
//! scenarios arrive with the anonymous layer in Phase 5.

use crate::clock::{EventQueue, VirtualClock};
use crate::error::{Result, SimError};
use crate::rng::DeterministicRng;
use crate::transcript::{Observation, Transcript};

/// Names of the calibration scenarios.
pub const CALIBRATION_UNIFORM: &str = "calibration-uniform";
/// Calibration scenario with a deliberately detectable timing pattern.
pub const CALIBRATION_TIMED: &str = "calibration-timed";

/// Discrete-event simulation state.
pub struct Simulation {
    /// Virtual clock.
    pub clock: VirtualClock,
    /// Pending events.
    pub queue: EventQueue<Observation>,
    /// Deterministic RNG.
    pub rng: DeterministicRng,
    transcript: Transcript,
}

impl Simulation {
    /// Create a simulation with an empty transcript.
    pub fn new(scenario: &str, seed: u64, senders: Vec<String>, duration_ms: u64) -> Self {
        Self {
            clock: VirtualClock::new(),
            queue: EventQueue::new(),
            rng: DeterministicRng::new(seed),
            transcript: Transcript {
                scenario: scenario.to_string(),
                seed,
                duration_ms,
                senders,
                observations: Vec::new(),
            },
        }
    }

    /// Schedule an observation at a logical time.
    pub fn schedule(&mut self, at_ms: u64, observation: Observation) {
        self.queue.schedule(at_ms, observation);
    }

    /// Replay all queued events in time order.
    pub fn run(mut self) -> Transcript {
        while let Some((at_ms, observation)) = self.queue.pop() {
            self.clock.advance_to(at_ms);
            self.transcript.observations.push(observation);
        }
        self.transcript
    }
}

/// Run a scenario by name with a deterministic seed.
pub fn run(name: &str, seed: u64) -> Result<Transcript> {
    match name {
        CALIBRATION_UNIFORM => Ok(calibration_uniform(seed)),
        CALIBRATION_TIMED => Ok(calibration_timed(seed)),
        other => Err(SimError::UnknownScenario(other.to_string())),
    }
}

/// All calibration scenarios do not model a protocol; they produce traffic
/// where every sender behaves identically (random timing and size).
fn calibration_uniform(seed: u64) -> Transcript {
    let senders = vec![
        "alice".to_string(),
        "bob".to_string(),
        "carol".to_string(),
        "dave".to_string(),
    ];
    let duration_ms = 60_000;
    let mut simulation = Simulation::new(CALIBRATION_UNIFORM, seed, senders.clone(), duration_ms);

    for (index, sender) in senders.iter().enumerate() {
        for _ in 0..200 {
            let at_ms = simulation.rng.below(duration_ms);
            let size = [256u64, 512, 1024][simulation.rng.below(3) as usize];
            let receiver = senders[(index + 1) % senders.len()].clone();
            simulation.schedule(
                at_ms,
                Observation {
                    at_ms,
                    sender: sender.clone(),
                    receiver,
                    size_bytes: size,
                    round_id: None,
                    participants: vec![],
                    cover: false,
                },
            );
        }
    }
    simulation.run()
}

/// Calibration scenario where `alice` emits on a fixed period (plus small
/// jitter) while the other senders stay uniformly random. The analyzer must
/// rank `alice` highest under timing correlation.
fn calibration_timed(seed: u64) -> Transcript {
    let senders = vec![
        "alice".to_string(),
        "bob".to_string(),
        "carol".to_string(),
        "dave".to_string(),
    ];
    let duration_ms = 60_000;
    let mut simulation = Simulation::new(CALIBRATION_TIMED, seed, senders.clone(), duration_ms);

    let mut at_ms = 0u64;
    while at_ms < duration_ms {
        let jitter = simulation.rng.below(20);
        let scheduled = at_ms + jitter;
        simulation.schedule(
            scheduled,
            Observation {
                at_ms: scheduled,
                sender: "alice".to_string(),
                receiver: "bob".to_string(),
                size_bytes: 512,
                round_id: None,
                participants: vec![],
                cover: false,
            },
        );
        at_ms += 1000;
    }

    for sender in senders.iter().filter(|sender| sender.as_str() != "alice") {
        for _ in 0..100 {
            let scheduled = simulation.rng.below(duration_ms);
            let size = [256u64, 512, 1024][simulation.rng.below(3) as usize];
            simulation.schedule(
                scheduled,
                Observation {
                    at_ms: scheduled,
                    sender: sender.clone(),
                    receiver: "alice".to_string(),
                    size_bytes: size,
                    round_id: None,
                    participants: vec![],
                    cover: false,
                },
            );
        }
    }
    simulation.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{coefficient_of_variation, entropy_from_counts};

    fn intervals(transcript: &Transcript, sender: &str) -> Vec<f64> {
        let mut times: Vec<u64> = transcript
            .observations
            .iter()
            .filter(|observation| observation.sender == sender && !observation.cover)
            .map(|observation| observation.at_ms)
            .collect();
        times.sort_unstable();
        times
            .windows(2)
            .map(|pair| (pair[1] - pair[0]) as f64)
            .collect()
    }

    #[test]
    fn unknown_scenario_is_an_error() {
        assert!(run("no-such-scenario", 1).is_err());
    }

    #[test]
    fn scenarios_are_deterministic() {
        let a = run(CALIBRATION_UNIFORM, 11).expect("a");
        let b = run(CALIBRATION_UNIFORM, 11).expect("b");
        assert_eq!(a, b);

        let c = run(CALIBRATION_UNIFORM, 12).expect("c");
        assert_ne!(a, c);
    }

    #[test]
    fn uniform_senders_have_similar_counts() {
        let transcript = run(CALIBRATION_UNIFORM, 5).expect("run");
        let counts: Vec<u64> = transcript
            .sender_counts()
            .into_iter()
            .map(|(_, count)| count)
            .collect();
        assert_eq!(counts.len(), 4);
        for count in counts {
            assert_eq!(count, 200);
        }
        // 4 equal senders: entropy is 2 bits.
        let entropy = entropy_from_counts(&[200, 200, 200, 200]);
        assert!((entropy - 2.0).abs() < 1e-12);
    }

    #[test]
    fn timed_scenario_reveals_alice_by_regularity() {
        let transcript = run(CALIBRATION_TIMED, 3).expect("run");
        let alice_cv =
            coefficient_of_variation(&intervals(&transcript, "alice")).expect("alice intervals");
        for other in ["bob", "carol", "dave"] {
            let other_cv = coefficient_of_variation(&intervals(&transcript, other))
                .expect("candidate intervals");
            assert!(
                alice_cv < other_cv / 10.0,
                "alice's fixed cadence (CV {alice_cv}) must stand out against \
                 {other} (CV {other_cv})"
            );
        }
    }

    #[test]
    fn virtual_time_covers_the_full_duration_without_wall_clock_wait() {
        let start = std::time::Instant::now();
        let transcript = run(CALIBRATION_UNIFORM, 1).expect("run");
        assert!(transcript.duration_ms == 60_000);
        assert!(transcript.observations.len() == 800);
        // The whole simulated minute must run in well under a second.
        assert!(start.elapsed().as_secs() < 5);
    }
}
