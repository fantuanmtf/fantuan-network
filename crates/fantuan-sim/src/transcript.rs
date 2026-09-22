//! Simulation transcripts: the JSON contract between the Rust collector and
//! the Python analyzer.

use serde::{Deserialize, Serialize};

/// One observed network event.
///
/// `sender` is ground truth recorded for analysis only; it is never part of
/// the simulated protocol output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// Logical time in milliseconds since simulation start.
    pub at_ms: u64,
    /// Ground-truth sender label.
    pub sender: String,
    /// Receiver label.
    pub receiver: String,
    /// Observed frame size in bytes.
    pub size_bytes: u64,
    /// DC-Net round id, when the event belongs to a round.
    pub round_id: Option<u64>,
    /// Round participants, when applicable.
    pub participants: Vec<String>,
    /// True when this frame is cover traffic.
    pub cover: bool,
}

/// Complete trace of one scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transcript {
    /// Scenario name.
    pub scenario: String,
    /// RNG seed used for the run.
    pub seed: u64,
    /// Scenario duration in logical milliseconds.
    pub duration_ms: u64,
    /// All sender labels known to the scenario.
    pub senders: Vec<String>,
    /// Observed events in time order.
    pub observations: Vec<Observation>,
}

impl Transcript {
    /// Number of observed non-cover events per sender.
    pub fn sender_counts(&self) -> Vec<(String, u64)> {
        let mut counts: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        for observation in &self.observations {
            if !observation.cover {
                *counts.entry(observation.sender.as_str()).or_insert(0) += 1;
            }
        }
        let mut pairs: Vec<(String, u64)> = counts
            .into_iter()
            .map(|(sender, count)| (sender.to_string(), count))
            .collect();
        pairs.sort();
        pairs
    }

    /// Per-sender event count per epoch of `epoch_ms`, in time order.
    ///
    /// Used by the analyzer for timing-correlation attacks.
    pub fn epoch_series(&self, epoch_ms: u64) -> std::collections::HashMap<String, Vec<f64>> {
        if epoch_ms == 0 {
            return std::collections::HashMap::new();
        }
        let epochs = (self.duration_ms / epoch_ms) as usize + 1;
        let mut series: std::collections::HashMap<String, Vec<f64>> = self
            .senders
            .iter()
            .map(|sender| (sender.clone(), vec![0.0; epochs]))
            .collect();
        for observation in &self.observations {
            let epoch = (observation.at_ms / epoch_ms) as usize;
            if epoch < epochs
                && let Some(values) = series.get_mut(&observation.sender)
            {
                values[epoch] += 1.0;
            }
        }
        series
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript() -> Transcript {
        Transcript {
            scenario: "test".to_string(),
            seed: 1,
            duration_ms: 3000,
            senders: vec!["alice".to_string(), "bob".to_string()],
            observations: vec![
                Observation {
                    at_ms: 10,
                    sender: "alice".to_string(),
                    receiver: "bob".to_string(),
                    size_bytes: 256,
                    round_id: None,
                    participants: vec![],
                    cover: false,
                },
                Observation {
                    at_ms: 1100,
                    sender: "alice".to_string(),
                    receiver: "bob".to_string(),
                    size_bytes: 256,
                    round_id: None,
                    participants: vec![],
                    cover: false,
                },
                Observation {
                    at_ms: 1200,
                    sender: "bob".to_string(),
                    receiver: "alice".to_string(),
                    size_bytes: 512,
                    round_id: None,
                    participants: vec![],
                    cover: true,
                },
            ],
        }
    }

    #[test]
    fn sender_counts_ignore_cover() {
        let counts = transcript().sender_counts();
        assert_eq!(counts, vec![("alice".to_string(), 2)]);
    }

    #[test]
    fn epoch_series_buckets_events() {
        let series = transcript().epoch_series(1000);
        assert_eq!(series["alice"], vec![1.0, 1.0, 0.0, 0.0]);
        // bob only sent cover traffic, but the series counts observations.
        assert_eq!(series["bob"], vec![0.0, 1.0, 0.0, 0.0]);
    }

    #[test]
    fn epoch_series_handles_zero_epoch() {
        assert!(transcript().epoch_series(0).is_empty());
    }
}
