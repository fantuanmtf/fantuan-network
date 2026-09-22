"""Turn a simulation transcript into an English anonymity report.

The analyzer implements the metric pipeline and the calibration attacker
models. Protocol-level anonymity claims are only made for scenarios whose
crate configuration is part of the anonymous layer (Phase 5); calibration
scenarios validate that the pipeline detects known leaks.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .metrics import (
    coefficient_of_variation,
    effective_set_size,
    entropy_from_counts,
    intervals,
    leak_gate,
    mean,
    mutual_information,
    pearson,
    variance,
)

EPOCH_MS = 1000
SIZE_BUCKETS = (256, 512, 1024)


@dataclass
class Transcript:
    """Parsed simulation transcript."""

    scenario: str
    seed: int
    duration_ms: int
    senders: list[str]
    observations: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Transcript":
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            scenario=raw["scenario"],
            seed=raw["seed"],
            duration_ms=raw["duration_ms"],
            senders=list(raw["senders"]),
            observations=list(raw["observations"]),
        )

    def sender_timestamps(self) -> dict[str, list[int]]:
        result: dict[str, list[int]] = {sender: [] for sender in self.senders}
        for observation in self.observations:
            if not observation.get("cover", False):
                result.setdefault(observation["sender"], []).append(observation["at_ms"])
        return result

    def epoch_series(self, key: str, epoch_ms: int = EPOCH_MS) -> dict[str, list[float]]:
        """Per-label counts per epoch; ``key`` is `sender` or `receiver`."""
        epochs = self.duration_ms // epoch_ms + 1
        series: dict[str, list[float]] = {sender: [0.0] * epochs for sender in self.senders}
        for observation in self.observations:
            label = observation[key]
            epoch = min(observation["at_ms"] // epoch_ms, epochs - 1)
            series.setdefault(label, [0.0] * epochs)[epoch] += 1.0
        return series


def interval_stats(timestamps: list[int]) -> dict[str, float]:
    """Mean, standard deviation and coefficient of variation of intervals."""
    values = intervals(timestamps)
    if len(values) < 2:
        return {"count": len(values), "mean": 0.0, "std": 0.0, "cv": float("nan")}
    mu = mean(values)
    sigma = math.sqrt(variance(values))
    return {
        "count": len(values),
        "mean": mu,
        "std": sigma,
        "cv": (sigma / mu) if mu else float("inf"),
    }


def periodicity_scores(transcript: Transcript) -> list[tuple[str, float]]:
    """Attacker ranking: lower interval CV means more regular, higher score."""
    scores: list[tuple[str, float]] = []
    for sender, timestamps in transcript.sender_timestamps().items():
        stats = interval_stats(timestamps)
        cv = stats["cv"]
        if cv != cv or cv == float("inf"):  # NaN or inf
            score = 0.0
        else:
            score = 1.0 / (1.0 + cv)
        scores.append((sender, score))
    scores.sort(key=lambda pair: pair[1], reverse=True)
    return scores


def link_correlations(transcript: Transcript) -> list[tuple[str, str, float]]:
    """Pearson correlation between candidate sender series and receiver series."""
    senders = transcript.epoch_series("sender")
    receivers = transcript.epoch_series("receiver")
    results: list[tuple[str, str, float]] = []
    for sender in transcript.senders:
        for receiver in transcript.senders:
            if sender == receiver:
                continue
            coefficient = pearson(senders.get(sender, []), receivers.get(receiver, []))
            if coefficient is not None:
                results.append((sender, receiver, coefficient))
    results.sort(key=lambda item: abs(item[2]), reverse=True)
    return results


def size_bucket(size: int) -> int:
    distances = [abs(size - bucket) for bucket in SIZE_BUCKETS]
    return distances.index(min(distances))


def gpa_metrics(transcript: Transcript) -> tuple[float, float]:
    """Per-round anonymity entropy and top-1 guess accuracy for a GPA."""
    per_round: dict[int, Counter] = {}
    for observation in transcript.observations:
        if observation.get("cover", False) or observation.get("round_id") is None:
            continue
        per_round.setdefault(observation["round_id"], Counter())[observation["sender"]] += 1

    entropies: list[float] = []
    accuracies: list[float] = []
    for counter in per_round.values():
        counts = list(counter.values())
        total = sum(counts)
        entropies.append(entropy_from_counts(counts))
        accuracies.append(max(counts) / total)
    return (
        mean(entropies) if entropies else 0.0,
        mean(accuracies) if accuracies else 0.0,
    )


def timing_attack(transcript: Transcript, epoch_ms: int = 1000) -> float:
    """Largest |Pearson r| between a candidate stream and aggregate traffic."""
    series = transcript.epoch_series("sender", epoch_ms)
    if not series:
        return 0.0
    epochs = len(next(iter(series.values())))
    aggregate = [
        sum(series[sender][epoch] for sender in series) for epoch in range(epochs)
    ]
    best = 0.0
    for values in series.values():
        coefficient = pearson(values, aggregate)
        if coefficient is not None:
            best = max(best, abs(coefficient))
    return best


def intersection_attack(transcript: Transcript) -> int:
    """Size of the intersection of per-round candidate sender sets."""
    rounds: dict[int, set[str]] = {}
    for observation in transcript.observations:
        if observation.get("cover", False) or observation.get("round_id") is None:
            continue
        rounds.setdefault(observation["round_id"], set()).add(observation["sender"])
    sets = [candidates for candidates in rounds.values() if candidates]
    if not sets:
        return 0
    return len(set.intersection(*sets))


def linkage_ratio(transcript: Transcript) -> tuple[int, int]:
    """(linked, total) consecutive round pairs with identical participant sets."""
    rounds: dict[int, set[str]] = {}
    for observation in transcript.observations:
        if observation.get("cover", False) or observation.get("round_id") is None:
            continue
        rounds.setdefault(observation["round_id"], set()).add(observation["sender"])
    ordered = [rounds[round_id] for round_id in sorted(rounds)]
    linked = 0
    for first, second in zip(ordered, ordered[1:]):
        if first == second:
            linked += 1
    return linked, max(0, len(ordered) - 1)


def attack_matrix(transcript: Transcript) -> dict[str, float | int]:
    """Run every attack over one transcript."""
    entropy, top1 = gpa_metrics(transcript)
    timing = timing_attack(transcript)
    intersection = intersection_attack(transcript)
    linked, total = linkage_ratio(transcript)
    return {
        "gpa_entropy_bits": entropy,
        "gpa_top1_accuracy": top1,
        "timing_max_abs_pearson": timing,
        "intersection_size": intersection,
        "linked_rounds": linked,
        "total_round_pairs": total,
    }


def sender_observation_pairs(transcript: Transcript, key: str) -> list[tuple[int, int]]:
    """Pairs of (sender index, observation bucket) for mutual information."""
    index = {sender: position for position, sender in enumerate(transcript.senders)}
    pairs: list[tuple[int, int]] = []
    for observation in transcript.observations:
        if observation.get("cover", False):
            continue
        if key == "size":
            bucket = size_bucket(int(observation["size_bytes"]))
        elif key == "epoch":
            bucket = observation["at_ms"] // EPOCH_MS
        else:
            raise ValueError(f"unknown observation key {key!r}")
        pairs.append((index[observation["sender"]], int(bucket)))
    return pairs


def build_report(transcript: Transcript) -> str:
    counts = {sender: len(times) for sender, times in transcript.sender_timestamps().items()}
    entropy = entropy_from_counts(counts.values())
    ideal = math.log2(len(transcript.senders)) if len(transcript.senders) > 1 else 0.0
    gate = leak_gate(entropy, len(transcript.senders))
    periodicity = periodicity_scores(transcript)
    correlations = link_correlations(transcript)
    mi_size = mutual_information(sender_observation_pairs(transcript, "size"))
    mi_epoch = mutual_information(sender_observation_pairs(transcript, "epoch"))

    lines: list[str] = []
    lines.append("# Anonymity Analysis Report")
    lines.append("")
    lines.append(f"- Scenario: `{transcript.scenario}`")
    lines.append(f"- Seed: `{transcript.seed}`")
    lines.append(f"- Simulated duration: {transcript.duration_ms} ms (virtual time)")
    lines.append(f"- Senders: {', '.join(transcript.senders)}")
    lines.append(f"- Observations: {len(transcript.observations)}")
    lines.append("")

    lines.append("## 1. Message-count anonymity")
    lines.append("")
    lines.append("| Sender | Messages |")
    lines.append("|--------|----------|")
    for sender in transcript.senders:
        lines.append(f"| {sender} | {counts[sender]} |")
    lines.append("")
    lines.append(f"- Entropy `H = {entropy:.4f}` bits")
    lines.append(f"- Ideal `log2(N) = {ideal:.4f}` bits")
    lines.append(f"- Leakage `log2(N) - H = {ideal - entropy:.4f}` bits")
    lines.append(f"- Effective anonymity set `2^H = {effective_set_size(entropy):.2f}`")
    lines.append(f"- Gate (leakage <= 1.0 bit): {'PASS' if gate else 'FAIL'}")
    lines.append("")

    lines.append("## 2. Timing regularity attack")
    lines.append("")
    lines.append("| Rank | Sender | Intervals | Mean dt | Std dt | CV | Score |")
    lines.append("|------|--------|-----------|---------|--------|----|-------|")
    for rank, (sender, score) in enumerate(periodicity, start=1):
        stats = interval_stats(transcript.sender_timestamps()[sender])
        lines.append(
            f"| {rank} | {sender} | {int(stats['count'])} | {stats['mean']:.2f} | "
            f"{stats['std']:.2f} | {stats['cv']:.4f} | {score:.4f} |"
        )
    lines.append("")
    lines.append(
        "A periodic sender keeps its interval CV near zero; uniform senders "
        "approach CV 1.0."
    )
    lines.append("")

    lines.append("## 3. Link timing correlation")
    lines.append("")
    if correlations:
        lines.append("| Sender | Receiver | Pearson r |")
        lines.append("|--------|----------|-----------|")
        for sender, receiver, coefficient in correlations[:10]:
            lines.append(f"| {sender} | {receiver} | {coefficient:+.4f} |")
    else:
        lines.append("_No non-constant series; correlation undefined._")
    lines.append("")

    lines.append("## 4. Mutual information")
    lines.append("")
    lines.append(f"- `I(sender; size bucket) = {mi_size:.4f}` bits")
    lines.append(f"- `I(sender; epoch) = {mi_epoch:.4f}` bits")
    lines.append("")

    lines.append("## 5. Attacker ranking (calibration)")
    lines.append("")
    top_sender, top_score = periodicity[0]
    lines.append(
        f"- Periodicity attacker top-1: **{top_sender}** (score {top_score:.4f})"
    )
    if correlations:
        sender, receiver, coefficient = correlations[0]
        lines.append(
            f"- Link-correlation attacker top pair: **{sender} -> {receiver}** "
            f"(r {coefficient:+.4f})"
        )
    lines.append("")

    lines.append("## 6. Attack matrix")
    lines.append("")
    attacks = attack_matrix(transcript)
    lines.append("| Attack | Result |")
    lines.append("|--------|--------|")
    lines.append(
        f"| GPA entropy (bits) | {attacks['gpa_entropy_bits']:.4f} |"
    )
    lines.append(
        f"| GPA top-1 accuracy | {attacks['gpa_top1_accuracy']:.4f} |"
    )
    lines.append(
        f"| Timing correlation max abs(r) | {attacks['timing_max_abs_pearson']:.4f} |"
    )
    lines.append(
        f"| Intersection attacker set size | {attacks['intersection_size']} |"
    )
    lines.append(
        f"| Participation linkage | {attacks['linked_rounds']}/"
        f"{attacks['total_round_pairs']} round pairs |"
    )
    lines.append("")
    lines.append(
        "N-1 collusion is algebraic: with every other participant colluding, "
        "the sender's share is reproducible (see `fantuan-anon` collusion "
        "tests)."
    )
    lines.append("")

    lines.append("## 7. Protocol gates")
    lines.append("")
    if transcript.scenario.startswith("dcnet"):
        sender_count = len([s for s in transcript.senders])
        gpa_bound = (1.0 / sender_count + 0.05) if sender_count else 1.0
        checks = [
            ("anonymity entropy >= log2(N) - 1 bit", ideal - entropy <= 1.0),
            ("I(sender; size bucket) < 0.05 bits", mi_size < 0.05),
            ("I(sender; epoch) < 0.05 bits", mi_epoch < 0.05),
            (
                f"GPA top-1 <= 1/N + 0.05 ({gpa_bound:.2f})",
                float(attacks["gpa_top1_accuracy"]) <= gpa_bound,
            ),
            (
                "intersection attack does not shrink the set",
                int(attacks["intersection_size"]) >= sender_count,
            ),
        ]
        for label, passed in checks:
            lines.append(f"- {'PASS' if passed else 'FAIL'}: {label}")
    else:
        lines.append("_Calibration scenario: protocol gates do not apply._")
    lines.append("")
    lines.append(
        "_DC-Net scenarios model share-level observations; calibration scenarios "
        "validate the metric pipeline itself._"
    )
    lines.append("")
    return "\n".join(lines)
