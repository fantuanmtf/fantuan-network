//! Anonymity metrics.
//!
//! These are the exact quantities used by the Python analyzer and asserted
//! by tests:
//!
//! * entropy `H = -Σ pᵢ log₂(pᵢ)` and effective anonymity-set size `2^H`;
//! * inter-arrival variance `Var(Δt)` and coefficient of variation;
//! * Pearson correlation `r = cov(X,Y)/(σx·σy)`;
//! * mutual information `I(S;O) = Σ p(s,o) log₂(p(s,o)/(p(s)p(o)))`.

/// Shannon entropy in bits from a probability distribution.
///
/// Entries that are zero or negative are ignored.
pub fn entropy(probabilities: &[f64]) -> f64 {
    probabilities
        .iter()
        .filter(|p| **p > 0.0)
        .map(|p| -p * p.log2())
        .sum()
}

/// Shannon entropy in bits from raw counts.
pub fn entropy_from_counts(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let probabilities: Vec<f64> = counts
        .iter()
        .map(|count| *count as f64 / total as f64)
        .collect();
    entropy(&probabilities)
}

/// Effective anonymity-set size `2^H`.
pub fn effective_set_size(entropy_bits: f64) -> f64 {
    2f64.powf(entropy_bits)
}

/// Arithmetic mean.
pub fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

/// Population variance.
pub fn variance(values: &[f64]) -> Option<f64> {
    let mean = mean(values)?;
    Some(
        values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / values.len() as f64,
    )
}

/// Coefficient of variation `σ/μ` (None when the mean is zero).
pub fn coefficient_of_variation(values: &[f64]) -> Option<f64> {
    let mean = mean(values)?;
    if mean == 0.0 {
        return None;
    }
    Some(variance(values)?.sqrt() / mean)
}

/// Population Pearson correlation coefficient.
///
/// Returns `None` for empty input, length mismatch or a constant series.
pub fn pearson(xs: &[f64], ys: &[f64]) -> Option<f64> {
    if xs.len() != ys.len() || xs.is_empty() {
        return None;
    }
    let mean_x = mean(xs)?;
    let mean_y = mean(ys)?;
    let mut covariance = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;
    for (x, y) in xs.iter().zip(ys) {
        covariance += (x - mean_x) * (y - mean_y);
        var_x += (x - mean_x).powi(2);
        var_y += (y - mean_y).powi(2);
    }
    if var_x == 0.0 || var_y == 0.0 {
        return None;
    }
    Some(covariance / (var_x.sqrt() * var_y.sqrt()))
}

/// Mutual information in bits between two discrete variables given as
/// paired observations.
///
/// Returns 0.0 for empty input.
pub fn mutual_information(pairs: &[(usize, usize)]) -> f64 {
    if pairs.is_empty() {
        return 0.0;
    }
    let total = pairs.len() as f64;

    let mut joint: std::collections::HashMap<(usize, usize), u64> =
        std::collections::HashMap::new();
    let mut left: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
    let mut right: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
    for (s, o) in pairs {
        *joint.entry((*s, *o)).or_insert(0) += 1;
        *left.entry(*s).or_insert(0) += 1;
        *right.entry(*o).or_insert(0) += 1;
    }

    let mut information = 0.0;
    for ((s, o), count) in joint {
        let p_so = count as f64 / total;
        let p_s = left[&s] as f64 / total;
        let p_o = right[&o] as f64 / total;
        information += p_so * (p_so / (p_s * p_o)).log2();
    }
    information
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_and_constant() {
        assert!((entropy_from_counts(&[1, 1, 1, 1]) - 2.0).abs() < 1e-12);
        assert!((entropy_from_counts(&[5, 0, 0, 0]) - 0.0).abs() < 1e-12);
        assert_eq!(entropy_from_counts(&[]), 0.0);
        // 8 equally likely senders: 3 bits.
        assert!((entropy_from_counts(&[1; 8]) - 3.0).abs() < 1e-12);
    }

    #[test]
    fn effective_set_size_matches_entropy() {
        assert!((effective_set_size(3.0) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn variance_and_cv() {
        let values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let var = variance(&values).expect("variance");
        assert!((var - 4.0).abs() < 1e-12);
        assert!(coefficient_of_variation(&[1.0, 1.0]).unwrap() == 0.0);
        assert!(coefficient_of_variation(&[0.0, 0.0]).is_none());
    }

    #[test]
    fn pearson_correlated_and_anticorrelated() {
        let xs = [1.0, 2.0, 3.0, 4.0];
        let ys = [2.0, 4.0, 6.0, 8.0];
        let zs = [-1.0, -2.0, -3.0, -4.0];
        assert!((pearson(&xs, &ys).unwrap() - 1.0).abs() < 1e-12);
        assert!((pearson(&xs, &zs).unwrap() + 1.0).abs() < 1e-12);
        assert!(pearson(&xs, &[1.0, 1.0, 1.0, 1.0]).is_none());
        assert!(pearson(&xs, &[1.0]).is_none());
    }

    #[test]
    fn mutual_information_perfect_and_independent() {
        // Perfectly correlated: I(S;O) = H(S) = 1 bit.
        let perfect = [(0, 0), (0, 0), (1, 1), (1, 1)];
        assert!((mutual_information(&perfect) - 1.0).abs() < 1e-12);

        // Independent: 0 bits.
        let independent = [(0, 0), (0, 1), (1, 0), (1, 1)];
        assert!(mutual_information(&independent).abs() < 1e-12);

        assert_eq!(mutual_information(&[]), 0.0);
    }
}
