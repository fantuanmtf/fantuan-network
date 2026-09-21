"""Anonymity metrics used by the analyzer.

Definitions match the Rust implementation in `crates/fantuan-sim/src/metrics.rs`
and `docs/TESTING.md`:

* entropy ``H = -sum(p_i * log2(p_i))``
* variance ``Var(dt)`` and coefficient of variation ``CV = sigma / mean``
* Pearson correlation ``r = cov(X, Y) / (sigma_x * sigma_y)``
* mutual information ``I(S;O) = sum(p(s,o) * log2(p(s,o) / (p(s) * p(o))))``
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Sequence


def entropy(probabilities: Iterable[float]) -> float:
    """Shannon entropy in bits."""
    return -sum(p * math.log2(p) for p in probabilities if p > 0.0)


def entropy_from_counts(counts: Iterable[int]) -> float:
    """Shannon entropy in bits from raw counts."""
    counts = [c for c in counts if c > 0]
    total = sum(counts)
    if total == 0:
        return 0.0
    return entropy(c / total for c in counts)


def effective_set_size(entropy_bits: float) -> float:
    """Effective anonymity-set size ``2^H``."""
    return 2.0**entropy_bits


def mean(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("mean of empty sequence")
    return sum(values) / len(values)


def variance(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("variance of empty sequence")
    mu = mean(values)
    return sum((v - mu) ** 2 for v in values) / len(values)


def coefficient_of_variation(values: Sequence[float]) -> float | None:
    if not values:
        return None
    mu = mean(values)
    if mu == 0.0:
        return None
    return math.sqrt(variance(values)) / mu


def pearson(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    """Population Pearson correlation; None on mismatch or constant series."""
    if len(xs) != len(ys) or not xs:
        return None
    mean_x = mean(xs)
    mean_y = mean(ys)
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    var_x = sum((x - mean_x) ** 2 for x in xs)
    var_y = sum((y - mean_y) ** 2 for y in ys)
    if var_x == 0.0 or var_y == 0.0:
        return None
    return covariance / math.sqrt(var_x * var_y)


def mutual_information(pairs: Sequence[tuple[int, int]]) -> float:
    """Mutual information in bits between two discrete variables."""
    if not pairs:
        return 0.0
    total = len(pairs)
    joint = Counter(pairs)
    left = Counter(s for s, _ in pairs)
    right = Counter(o for _, o in pairs)
    information = 0.0
    for (s, o), count in joint.items():
        p_so = count / total
        p_s = left[s] / total
        p_o = right[o] / total
        information += p_so * math.log2(p_so / (p_s * p_o))
    return information


def intervals(timestamps_ms: Sequence[int]) -> list[float]:
    """Inter-arrival times of sorted timestamps."""
    ordered = sorted(timestamps_ms)
    return [float(b - a) for a, b in zip(ordered, ordered[1:])]


def leak_gate(entropy_bits: float, sender_count: int, budget_bits: float = 1.0) -> bool:
    """True when the entropy stays within `budget_bits` of the ideal."""
    ideal = math.log2(sender_count) if sender_count > 1 else 0.0
    return ideal - entropy_bits <= budget_bits
