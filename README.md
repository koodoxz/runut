# Runut (MIMIR-RS) ᛘᛁᛘᛁᚾᚾ

> *"Wisest of the Gods, Guardian of the Well of Knowledge"*
> **Rust Edition - Ultra Blazzing Fast**
>
> Public release name: **Runut** (Indonesian: "to trace/track sequentially"). Internal crate/binary name remains `mimir` / `mimir-rs`.

[![Rust](https://img.shields.io/badge/Rust-1.75+-000000?style=flat&logo=rust)](https://www.rust-lang.org/)

High-performance DNS Guardian rebuilt from scratch in Rust. Zero GC, predictable latency, 4x faster than Go version.

## Performance

| Metric | Go | Rust | Improvement |
|--------|-----|------|-------------|
| QPS | 5,000 | **20,000+** | 4x |
| Latency | 0.69ms | **0.2ms** | 3x |
| P99 | 8ms | **<1ms** | 8x |
| Memory | 81MB | **<30MB** | 3x |

*Self-reported, single-operator benchmark against an earlier internal Go
implementation — not independently reproduced or peer-reviewed. Treat as
directional, not a guarantee.*

## Features

- ⚡ **Zero GC** - Predictable sub-millisecond latency
- 🛡️ **Full Protocol Support** - UDP, TCP, DoT, DoH, DoQ
- 💾 **Sharded Cache** - Lock-free concurrent LRU
- 🔒 **Bloom Filter** - O(1) blocklist lookup
- 🔗 **Threat-Feed Integration** - Real-time threat sync with a compatible WAF/shield backend (e.g. [Tameng](https://github.com/koodoxz/tameng))
- 🧬 **DGA Detection** - Heuristic scoring for algorithmically-generated domains, alert-only, disabled by default
- 🕳️ **DNS-Tunneling Detection** - Flags domains with an unusually high distinct-subdomain query rate, alert-only, disabled by default
- 📊 **Prometheus Metrics** - Full observability

## Quick Start

```bash
# Build
cargo build --release

# Run
sudo ./target/release/mimir --config configs/mimir.yaml

# Or with CLI args
sudo ./target/release/mimir --listen 0.0.0.0:53 --upstream 1.1.1.1:53
```

## Configuration

```yaml
# configs/mimir.yaml
listen:
  udp: "0.0.0.0:53"
  tcp: "0.0.0.0:53"
  dot: "0.0.0.0:853"   # DNS-over-TLS
  doh: "0.0.0.0:443"   # DNS-over-HTTPS
  doq: "0.0.0.0:853"   # DNS-over-QUIC

upstream:
  servers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  timeout_ms: 2000

cache:
  enabled: true
  size: 50000
  shards: 64

blocklist:
  enabled: true
  bloom_size: 1000000
  sources:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

svalinn:
  enabled: true
  url: "https://your-shield-instance.example.com"
  api_key: "${SVALINN_API_KEY}"
  sync_interval_secs: 300

# DGA (Domain Generation Algorithm) heuristic detection -- alert-only,
# logs a warning and increments a counter, never blocks a query.
dga:
  enabled: false
  threshold: 0.5

# DNS-tunneling heuristic detection -- alert-only. Flags a registrable
# domain once it has generated more than distinct_subdomain_threshold
# distinct subdomains within the tracker's retention window (bounded by
# the two capacity settings below), never blocks a query.
tunnel:
  enabled: false
  distinct_subdomain_threshold: 30
  tracker_outer_capacity: 2000
  tracker_inner_capacity: 256

metrics:
  enabled: true
  listen: "0.0.0.0:9153"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MIMIR-RS DNS Server                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ UDP/TCP/DoT │  │   Cache     │  │   Blocklist         │  │
│  │ DoH/DoQ     │  │ (Sharded)   │  │   (Bloom Filter)    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Forwarder  │  │   Metrics   │  │  Threat-Feed Client  │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Cross-compile for Linux (from Windows)
cargo build --release --target x86_64-unknown-linux-gnu
```

## Testing

```bash
# Run tests
cargo test

# Benchmark
cargo bench

# DNS performance test
dnsperf -s 127.0.0.1 -d queries.txt -l 60 -c 50 -Q 10000
```

## License

MIT License - Runut Contributors
