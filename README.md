# fantuan-network

Fantuan Network — a six-layer anonymous networking stack built on I2P.

```
Application (IRC / BBS / File / DM)
        |
Message Protocol (Message / Object)
        |
Anonymous (DC-Net / Mix / Padding) | Storage (Chunk / DHT / Replication) | Identity (OpenPGP / Trust Graph)
        |
Transport (I2P Tunnel / Noise / Session Manager)
        |
Network Node (Peer Discovery / Routing / Relay)
```

**Status:** Phase 3 complete — OpenPGP identity and descriptors, CBOR message
envelope, I2P SAM v3 + Noise sessions with identity binding, signed trust
graph, gossip discovery, end-to-end encrypted relay routing, channels and
forums with offline history sync, a TUI client, a local IRC bridge, and the
offline simulation/analysis pipeline. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Repository layout

| Path | Purpose |
|------|---------|
| `crates/fantuan-core` | errors, configuration, secure file I/O, time |
| `crates/fantuan-identity` | OpenPGP key hierarchy, descriptors, trust graph |
| `crates/fantuan-msg` | CBOR message/object envelope, signing |
| `crates/fantuan-transport` | SAM v3 (I2P), Noise sessions, connection pool |
| `crates/fantuan-sim` | offline discrete-event anonymity simulator |
| `crates/fantuan-node` | `fantuan-node` binary |
| `analysis/` | Python statistical analysis of simulation transcripts |
| `docs/` | English project documentation |
| `reports/` | English test and anonymity-analysis reports |

## Build and test

Native dependencies: `libnettle-dev`, `libgmp-dev` (OpenPGP backend).

```bash
cargo build --workspace --release
cargo test --workspace --release
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
bash scripts/check-file-lines.sh
```

Local I2P integration tests require a running i2pd with the SAM bridge:

```bash
bash scripts/i2p-dev.sh
cargo test -p fantuan-transport --features i2p-integration -- --ignored
```

## Engineering conventions

1. Every source file stays at or below 1000 lines; CI enforces this.
2. All documentation, reports, comments, identifiers and commit messages are
   written in English.
3. Every security claim ships with an adversarial test.
4. Unwired functionality is deleted or explicitly documented as unwired.
5. Protocol changes update `docs/PROTOCOL.md` before implementation.

## License

BSD 3-Clause. See [`LICENSE`](LICENSE).
