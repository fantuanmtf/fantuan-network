//! Deterministic pseudo-random generator for reproducible simulations.
//!
//! SplitMix64: tiny, fast and platform independent, so a seed produces the
//! same transcript on every machine.

/// Deterministic RNG.
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Create an RNG from a seed.
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9e37_79b9_7f4a_7c15),
        }
    }

    /// Next raw 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform value in `0..bound` (`0` when bound is zero).
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    /// Uniform value in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform integer in `min..=max`.
    pub fn range(&mut self, min: u64, max: u64) -> u64 {
        if max <= min {
            return min;
        }
        min + self.below(max - min + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = DeterministicRng::new(42);
        let mut b = DeterministicRng::new(42);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = DeterministicRng::new(1);
        let mut b = DeterministicRng::new(2);
        let differ = (0..16).any(|_| a.next_u64() != b.next_u64());
        assert!(differ);
    }

    #[test]
    fn below_respects_bound() {
        let mut rng = DeterministicRng::new(7);
        for _ in 0..1000 {
            assert!(rng.below(5) < 5);
        }
        assert_eq!(rng.below(0), 0);
    }

    #[test]
    fn unit_is_in_range() {
        let mut rng = DeterministicRng::new(9);
        for _ in 0..1000 {
            let value = rng.unit();
            assert!((0.0..1.0).contains(&value));
        }
    }
}
