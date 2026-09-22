# Fantuan Network — Testing

## 1. Test levels

| Level | Scope | Command | Runs in CI |
|-------|-------|---------|------------|
| Unit | per-module logic and parsers | `cargo test --workspace` | yes |
| Adversarial | spoofing, replay, tamper, oversize | included in unit suites | yes |
| Simulation | offline anonymity analysis (fast seeds) | `cargo test -p fantuan-sim` | yes |
| Simulation (long) | large scenarios, many seeds | `scripts/run-anon-analysis.sh` | no (manual/nightly) |
| I2P integration | real SAM sessions against i2pd | `cargo test -p fantuan-transport --features i2p-integration -- --ignored` | no (feature-gated) |

## 2. Adversarial test rules

- Every security claim is backed by a test that attempts to break it.
- At minimum: forged signatures, replayed frames, tampered descriptors,
  mismatched Noise static keys, oversized inputs, non-canonical encodings.
- Tests must not require network access.

## 3. Anonymity metrics

The simulator produces JSON transcripts; the Python analyzer computes:

| Metric | Definition | Gate |
|--------|------------|------|
| Anonymity entropy | `H = -Σ pᵢ log₂(pᵢ)`; leakage `log₂N − H`; effective set `2^H` | `H ≥ log₂N − δ` |
| Inter-arrival variance | `Var(Δt)`, coefficient of variation `CV = σ/μ` | below scenario threshold |
| Pearson correlation | `r = cov(X,Y)/(σx·σy)` | `|r| < ρ` |
| Mutual information | `I(S;O) = Σ p(s,o) log₂(p(s,o)/(p(s)p(o)))` | `I < ε` |
| Attack success | top-1 accuracy, precision/recall, anonymity-set size | below scenario budget |

Attack models covered: global passive adversary, partial adversarial nodes,
timing correlation, intersection attack, n−1 attack, round-participation
linkage. The full matrix and results live in [`ATTACKS.md`](ATTACKS.md).

Run the attack suite:

```bash
cargo test -p fantuan-sim -p fantuan-anon    # unit + attack assertions
bash scripts/run-anon-analysis.sh dcnet-mesh 11
bash scripts/run-anon-analysis.sh attack-selective 2
```

## 4. Conventions

- All test names, fixtures and reports are English.
- Simulation output is deterministic given `--seed`.
- Reports are written to `reports/` in Markdown.
- No test may exceed the 1000-line file limit; split suites by concern.
