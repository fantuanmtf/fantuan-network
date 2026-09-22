# Fantuan Network — Dependencies

This file is the single log for native dependencies, mixed-language
components and evaluated-then-rejected alternatives. Every non-Rust
dependency must be listed here with its purpose and fallback.

## 1. Native (C/C++) dependencies

| Dependency | Used by | Purpose | Notes / fallback |
|------------|---------|---------|------------------|
| nettle, gmp | `sequoia-openpgp` (`crypto-nettle`) | OpenPGP cryptography | System packages: `libnettle-dev`, `libgmp-dev`. Fallback: `crypto-rust` feature (pure Rust, slower). |
| SQLite (bundled) | `rusqlite` (`bundled`) | user and trust data | Compiled from vendored SQLite; no system package required. Fallback: `redb` for all tables (loses SQL). |

## 2. Mixed-language components

| Component | Language | Contract | Why not Rust |
|-----------|----------|----------|--------------|
| `analysis/` | Python | reads simulator JSON, writes English reports | mature statistics ecosystem; isolated from the network stack |

## 3. Rust dependency selection notes

| Crate | Purpose | Notes |
|-------|---------|-------|
| `tokio` | async runtime | multi-thread runtime, TCP, timers, signals |
| `serde` + `ciborium` | CBOR envelope | canonical object encoding |
| `toml` | node configuration | |
| `clap` | node CLI | derive API |
| `sequoia-openpgp` | OpenPGP identity | LGPL-2.0-or-later; dynamically-influenced licensing is reviewed before release |
| `snow` | Noise protocol | `Noise_XX_25519_ChaChaPoly_BLAKE2s` |
| `yosemite` | I2P SAM v3 | MIT, async/tokio, supports STREAM ACCEPT/CONNECT and destination generation |
| `rusqlite` | SQLite | bundled build |
| `blake3` | object ids | |
| `getrandom` | key material | OS entropy |
| `zeroize` | secret hygiene | secrets cleared on drop |
| `ratatui` + `crossterm` | TUI client | terminal rendering and input |
| `redb` | chunk cache | pure-Rust embedded key/value store with a byte budget |
| `hkdf` + `sha2` | DC-Net pair shares | RFC 5869 key expansion over X25519 secrets |
| `chacha20poly1305` | chunk encryption | AEAD with per-chunk random nonces and AAD binding |
| `rusqlite` | message store | channel/forum history, dedup and sync |
| `tracing` + `tracing-subscriber` | structured logging | |

## 4. Evaluated I2P SAM clients

| Crate | Version | Verdict | Reason |
|-------|---------|---------|--------|
| `yosemite` | 0.7.0 | **selected** | MIT, async (tokio), STREAM ACCEPT/CONNECT, forwarding, destination generation with private-key persistence |
| `i2p_client` | 0.2.9 | rejected | unmaintained since 2019, edition 2018, clap 2 / nom 2, no STREAM ACCEPT |
| `ri2p` | 1.0.0 | rejected | smaller API surface, no destination persistence story |
| `i2p` | 0.0.1 | rejected | placeholder crate |

## 5. Crate size policy

The 1000-line limit is enforced by `scripts/check-file-lines.sh` over all
tracked `*.rs` and `*.py` files. Files that grow past the limit are split by
module boundary.
