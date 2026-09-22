//! De-anonymization attack implementations over simulation transcripts.
//!
//! These are the attacks the security report evaluates. They are pure
//! functions so they can be asserted in CI and reproduced by the Python
//! analyzer:
//!
//! * **GPA** — a global passive adversary measures the per-round anonymity
//!   set (entropy and top-1 accuracy).
//! * **Timing correlation** — Pearson correlation between candidate sender
//!   streams and the aggregate traffic.
//! * **Intersection** — intersect per-round candidate sets; selective
//!   participation collapses the set.
//! * **Participation linkage** — fraction of consecutive rounds whose
//!   participant sets are identical (pseudonym linkage).
//!
//! N−1 collusion is algebraic and tested with real share math in
//! `fantuan-anon` (`colluding_*` tests).

use crate::metrics::{entropy_from_counts, pearson};
use crate::transcript::Transcript;
use std::collections::{HashMap, HashSet};

/// Result of running the attack suite over one transcript.
#[derive(Debug, Clone, PartialEq)]
pub struct AttackReport {
    /// Mean per-round anonymity-set entropy in bits (GPA).
    pub gpa_entropy_bits: f64,
    /// Mean per-round top-1 accuracy of the GPA guess.
    pub gpa_top1_accuracy: f64,
    /// Largest |Pearson r| across candidate senders (timing attacker).
    pub timing_max_abs_pearson: f64,
    /// Size of the intersection of per-round candidate sets.
    pub intersection_size: usize,
    /// Consecutive round pairs with identical participant sets.
    pub linked_rounds: usize,
    /// Consecutive round pairs total.
    pub total_round_pairs: usize,
}

/// Run the attack suite.
pub fn analyze(transcript: &Transcript) -> AttackReport {
    let rounds = rounds_of(transcript);

    let mut entropy_sum = 0.0;
    let mut top1_sum = 0.0;
    let mut counted = 0.0;
    for observations in rounds.values() {
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for observation in observations {
            if !observation.cover {
                *counts.entry(observation.sender.as_str()).or_insert(0) += 1;
            }
        }
        if counts.is_empty() {
            continue;
        }
        let values: Vec<u64> = counts.values().copied().collect();
        entropy_sum += entropy_from_counts(&values);
        let total: u64 = values.iter().sum();
        let top: u64 = values.iter().copied().max().unwrap_or(0);
        top1_sum += top as f64 / total as f64;
        counted += 1.0;
    }
    let (gpa_entropy_bits, gpa_top1_accuracy) = if counted > 0.0 {
        (entropy_sum / counted, top1_sum / counted)
    } else {
        (0.0, 0.0)
    };

    // Timing correlation against the aggregate per-epoch series.
    let series = transcript.epoch_series(1000);
    let epochs = series.values().next().map(Vec::len).unwrap_or(0);
    let aggregate: Vec<f64> = (0..epochs)
        .map(|epoch| {
            series
                .values()
                .map(|values| values.get(epoch).copied().unwrap_or(0.0))
                .sum()
        })
        .collect();
    let mut timing_max_abs_pearson: f64 = 0.0;
    for values in series.values() {
        if let Some(coefficient) = pearson(values, &aggregate) {
            timing_max_abs_pearson = timing_max_abs_pearson.max(coefficient.abs());
        }
    }

    // Intersection of per-round candidate sets.
    let mut intersection: Option<HashSet<&str>> = None;
    for observations in rounds.values() {
        let candidates: HashSet<&str> = observations
            .iter()
            .filter(|observation| !observation.cover)
            .map(|observation| observation.sender.as_str())
            .collect();
        if candidates.is_empty() {
            continue;
        }
        intersection = Some(match intersection {
            Some(current) => current.intersection(&candidates).copied().collect(),
            None => candidates,
        });
    }
    let intersection_size = intersection.map(|set| set.len()).unwrap_or(0);

    // Participation linkage between consecutive rounds.
    let ordered: Vec<&Vec<crate::transcript::Observation>> = rounds.values().collect();
    let mut linked_rounds = 0;
    let mut total_round_pairs = 0;
    let participant_set = |observations: &[crate::transcript::Observation]| -> Vec<String> {
        let mut set: Vec<String> = observations
            .iter()
            .filter(|observation| !observation.cover)
            .map(|observation| observation.sender.clone())
            .collect();
        set.sort();
        set.dedup();
        set
    };
    for pair in ordered.windows(2) {
        total_round_pairs += 1;
        if participant_set(pair[0]) == participant_set(pair[1]) {
            linked_rounds += 1;
        }
    }

    AttackReport {
        gpa_entropy_bits,
        gpa_top1_accuracy,
        timing_max_abs_pearson,
        intersection_size,
        linked_rounds,
        total_round_pairs,
    }
}

fn rounds_of(
    transcript: &Transcript,
) -> std::collections::BTreeMap<u64, Vec<crate::transcript::Observation>> {
    let mut rounds: std::collections::BTreeMap<u64, Vec<crate::transcript::Observation>> =
        std::collections::BTreeMap::new();
    for observation in &transcript.observations {
        if let Some(round_id) = observation.round_id {
            rounds
                .entry(round_id)
                .or_default()
                .push(observation.clone());
        }
    }
    rounds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{DCNET_COVER, DCNET_MESH, run};

    #[test]
    fn dcnet_mesh_hides_the_sender_from_a_gpa() {
        let transcript = run(DCNET_MESH, 3).expect("run");
        let report = analyze(&transcript);
        let ideal = 3f64.log2();
        assert!(
            (report.gpa_entropy_bits - ideal).abs() < 1e-9,
            "entropy {} should equal log2(3)",
            report.gpa_entropy_bits
        );
        assert!(
            (report.gpa_top1_accuracy - 1.0 / 3.0).abs() < 1e-9,
            "top-1 {} should be chance level",
            report.gpa_top1_accuracy
        );
        assert_eq!(report.intersection_size, 3, "no set shrinkage");
        assert_eq!(report.linked_rounds, report.total_round_pairs);
    }

    #[test]
    fn selective_participation_collapses_the_anonymity_set() {
        let transcript = run(crate::scenario::ATTACK_SELECTIVE, 1).expect("run");
        let report = analyze(&transcript);
        assert_eq!(
            report.intersection_size, 1,
            "the intersection attack isolates the always-present sender"
        );
    }

    #[test]
    fn cover_traffic_does_not_weaken_the_gpa_result() {
        let transcript = run(DCNET_COVER, 5).expect("run");
        let report = analyze(&transcript);
        let ideal = 3f64.log2();
        assert!((report.gpa_entropy_bits - ideal).abs() < 1e-9);
    }
}
