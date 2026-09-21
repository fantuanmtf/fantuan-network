//! Web-of-trust scoring.
//!
//! Trust is a worklist fixpoint over directed relationships. The effective
//! contribution of one relationship is `min(signer trust, declared level)`;
//! a subject becomes `Full` with one full contribution or two marginal ones,
//! and `Marginal` with one marginal contribution. Levels only ever grow, so
//! the fixpoint terminates and the result is independent of iteration order.

use crate::error::Result;
use crate::trust::{Relationship, TrustLevel, TrustStore};
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum peers scored in one refresh.
const SCORE_LIMIT: usize = 1_000_000;

/// Scoring view over a [`TrustStore`].
pub struct TrustGraph<'a> {
    store: &'a TrustStore,
    own: String,
    overrides: HashMap<String, TrustLevel>,
    cache: Option<HashMap<String, TrustLevel>>,
}

impl<'a> TrustGraph<'a> {
    /// Create a graph rooted at our own fingerprint.
    pub fn new(store: &'a TrustStore, own: impl Into<String>) -> Self {
        Self {
            store,
            own: own.into(),
            overrides: HashMap::new(),
            cache: None,
        }
    }

    /// Pin a trust level, bypassing computation.
    pub fn set_override(&mut self, fingerprint: &str, level: TrustLevel) {
        self.overrides.insert(fingerprint.to_string(), level);
        self.cache = None;
    }

    /// Drop the cached score map.
    pub fn invalidate(&mut self) {
        self.cache = None;
    }

    fn ensure(&mut self) -> Result<()> {
        if self.cache.is_none() {
            let relationships = self.store.relationships()?;
            self.cache = Some(Self::compute(&self.own, &self.overrides, &relationships));
        }
        Ok(())
    }

    /// Trust level of one fingerprint.
    pub fn trust_of(&mut self, fingerprint: &str) -> Result<TrustLevel> {
        if fingerprint == self.own {
            return Ok(TrustLevel::Ultimate);
        }
        if let Some(level) = self.overrides.get(fingerprint) {
            return Ok(*level);
        }
        self.ensure()?;
        Ok(self
            .cache
            .as_ref()
            .and_then(|map| map.get(fingerprint))
            .copied()
            .unwrap_or(TrustLevel::Unknown))
    }

    /// The full score map (rooted at our key).
    pub fn trust_map(&mut self) -> Result<&HashMap<String, TrustLevel>> {
        self.ensure()?;
        Ok(self.cache.as_ref().expect("cache is populated"))
    }

    /// Shortest introduction path from our key to `fingerprint`.
    ///
    /// Returns full fingerprints, starting with our own.
    pub fn trust_path(&mut self, fingerprint: &str) -> Result<Vec<String>> {
        let relationships = self.store.relationships()?;
        let mut queue: VecDeque<Vec<String>> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();
        queue.push_back(vec![self.own.clone()]);
        visited.insert(self.own.clone());

        while let Some(path) = queue.pop_front() {
            let current = path.last().cloned().unwrap_or_default();
            if current == fingerprint {
                return Ok(path);
            }
            for relationship in &relationships {
                if relationship.signer == current
                    && !visited.contains(&relationship.subject)
                    && !self.overrides.contains_key(&relationship.subject)
                {
                    visited.insert(relationship.subject.clone());
                    let mut next = path.clone();
                    next.push(relationship.subject.clone());
                    queue.push_back(next);
                }
            }
        }
        Ok(Vec::new())
    }

    /// Persist computed scores for all known peers; returns the update count.
    pub fn refresh_scores(&mut self) -> Result<usize> {
        self.ensure()?;
        let peers = self.store.peers(SCORE_LIMIT)?;
        let scores = self.cache.as_ref().expect("cache is populated");
        let mut updated = 0;
        for peer in peers {
            let level = scores
                .get(&peer.fingerprint)
                .copied()
                .unwrap_or(TrustLevel::Unknown);
            let score = level.to_score();
            if (peer.trust_score - score).abs() > f64::EPSILON {
                self.store.set_trust_score(&peer.fingerprint, score)?;
                updated += 1;
            }
        }
        Ok(updated)
    }

    /// Pure fixpoint computation over a relationship set.
    pub fn compute(
        own: &str,
        overrides: &HashMap<String, TrustLevel>,
        relationships: &[Relationship],
    ) -> HashMap<String, TrustLevel> {
        let mut trust: HashMap<String, TrustLevel> = HashMap::new();
        trust.insert(own.to_string(), TrustLevel::Ultimate);
        for (fingerprint, level) in overrides {
            trust.insert(fingerprint.clone(), *level);
        }

        let subjects: HashSet<&str> = relationships
            .iter()
            .map(|relationship| relationship.subject.as_str())
            .collect();

        loop {
            let mut changed = false;
            for subject in &subjects {
                if *subject == own || overrides.contains_key(*subject) {
                    continue;
                }
                let mut full = 0usize;
                let mut marginal = 0usize;
                for relationship in relationships
                    .iter()
                    .filter(|relationship| relationship.subject == *subject)
                {
                    let signer = trust
                        .get(&relationship.signer)
                        .copied()
                        .unwrap_or(TrustLevel::Unknown);
                    let declared = TrustLevel::from_i32(relationship.level as i32);
                    let contribution = signer.min(declared);
                    if contribution >= TrustLevel::Full {
                        full += 1;
                    } else if contribution >= TrustLevel::Marginal {
                        marginal += 1;
                    }
                }
                let new_level = if full >= 1 || marginal >= 2 {
                    TrustLevel::Full
                } else if marginal >= 1 {
                    TrustLevel::Marginal
                } else {
                    TrustLevel::Unknown
                };
                let current = trust.get(*subject).copied();
                if current != Some(new_level) {
                    trust.insert(subject.to_string(), new_level);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        trust
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(signer: &str, subject: &str, level: u8) -> Relationship {
        Relationship {
            signer: signer.to_string(),
            subject: subject.to_string(),
            level,
            updated_at: 0,
            signature: Vec::new(),
        }
    }

    fn score(own: &str, relationships: &[Relationship]) -> HashMap<String, TrustLevel> {
        TrustGraph::compute(own, &HashMap::new(), relationships)
    }

    #[test]
    fn direct_signature_is_full() {
        let map = score("OWN", &[rel("OWN", "BOB", 2)]);
        assert_eq!(map["BOB"], TrustLevel::Full);
    }

    #[test]
    fn chain_is_full() {
        let map = score("OWN", &[rel("OWN", "BOB", 2), rel("BOB", "CAROL", 2)]);
        assert_eq!(map["BOB"], TrustLevel::Full);
        assert_eq!(map["CAROL"], TrustLevel::Full);
    }

    #[test]
    fn result_is_order_independent() {
        let mut relationships = vec![rel("OWN", "BOB", 2), rel("BOB", "CAROL", 2)];
        let first = score("OWN", &relationships);
        relationships.reverse();
        let second = score("OWN", &relationships);
        assert_eq!(first["CAROL"], TrustLevel::Full);
        assert_eq!(second["CAROL"], TrustLevel::Full);
    }

    #[test]
    fn signature_level_caps_signer_trust() {
        // A Full introducer granting only Marginal yields Marginal.
        let map = score("OWN", &[rel("OWN", "BOB", 2), rel("BOB", "CAROL", 1)]);
        assert_eq!(map["CAROL"], TrustLevel::Marginal);
    }

    #[test]
    fn two_marginal_makes_full() {
        let map = score(
            "OWN",
            &[
                rel("OWN", "BOB", 2),
                rel("OWN", "CAROL", 2),
                rel("BOB", "TARGET", 1),
                rel("CAROL", "TARGET", 1),
            ],
        );
        assert_eq!(map["TARGET"], TrustLevel::Full);
    }

    #[test]
    fn mutual_signing_without_own_path_is_unknown() {
        let map = score("OWN", &[rel("A", "B", 2), rel("B", "A", 2)]);
        assert_eq!(map["A"], TrustLevel::Unknown);
        assert_eq!(map["B"], TrustLevel::Unknown);
    }

    #[test]
    fn override_never_blocks() {
        let mut overrides = HashMap::new();
        overrides.insert("EVE".to_string(), TrustLevel::Never);
        let map = TrustGraph::compute("OWN", &overrides, &[rel("OWN", "EVE", 2)]);
        assert_eq!(map["EVE"], TrustLevel::Never);
    }

    #[test]
    fn cycles_terminate() {
        let map = score(
            "OWN",
            &[rel("OWN", "A", 2), rel("A", "B", 2), rel("B", "A", 2)],
        );
        assert_eq!(map["A"], TrustLevel::Full);
        assert_eq!(map["B"], TrustLevel::Full);
    }

    #[test]
    fn store_backed_trust_and_path() {
        let store = TrustStore::in_memory().expect("store");
        store.upsert_peer("OWN", "me", "aa", 1).expect("own");
        store.upsert_peer("BOB", "bob", "bb", 1).expect("bob");
        store.upsert_peer("CAROL", "carol", "cc", 1).expect("carol");
        store
            .set_relationship("OWN", "BOB", 2, 10, b"sig1")
            .expect("rel1");
        store
            .set_relationship("BOB", "CAROL", 2, 11, b"sig2")
            .expect("rel2");

        let mut graph = TrustGraph::new(&store, "OWN");
        assert_eq!(graph.trust_of("CAROL").unwrap(), TrustLevel::Full);
        assert_eq!(graph.trust_of("OWN").unwrap(), TrustLevel::Ultimate);
        assert_eq!(graph.trust_of("NOBODY").unwrap(), TrustLevel::Unknown);

        let path = graph.trust_path("CAROL").unwrap();
        assert_eq!(path, vec!["OWN", "BOB", "CAROL"]);

        let updated = graph.refresh_scores().unwrap();
        assert!(updated >= 2, "carol and bob scores are persisted");
        assert_eq!(store.get_peer("CAROL").unwrap().unwrap().trust_score, 0.8);
    }

    #[test]
    fn override_in_store_graph() {
        let store = TrustStore::in_memory().expect("store");
        let mut graph = TrustGraph::new(&store, "OWN");
        graph.set_override("EVE", TrustLevel::Never);
        assert_eq!(graph.trust_of("EVE").unwrap(), TrustLevel::Never);
    }
}
