# Runut (RUNUT) ᛘᛁᛘᛁᚾᚾ

> **High-Performance Autonomous DNS Guardian — Engineered in Rust**  
> Sub-millisecond latency, zero garbage collection, multi-protocol resolution, and real-time active threat defense.

[![Rust](https://img.shields.io/badge/Rust-1.75+-000000?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocols](https://img.shields.io/badge/Protocols-UDP%20%7C%20TCP%20%7C%20DoT%20%7C%20DoH%20%7C%20DoQ-green.svg)](#features)

---

## ⚡ Executive Summary

**Runut** (Indonesian: *"to trace / track systematically"*) is an enterprise-grade DNS resolver and security gateway built in pure Rust. It is engineered to replace legacy DNS servers with a zero-cost abstraction stack that eliminates GC pauses and withstands high-QPS network stress.

### Benchmarks (Directional Baseline)
| Metric | Go Reference Implementation | Runut (Rust) | Delta |
| :--- | :--- | :--- | :--- |
| **Throughput** | ~5,000 QPS | **20,000+ QPS** | **4x Faster** |
| **Median Latency** | 0.69 ms | **0.20 ms** | **3.5x Lower** |
| **P99 Latency** | ~8.00 ms | **< 1.00 ms** | **8x Predictability** |
| **Memory Footprint** | ~81 MB | **< 30 MB** | **63% Reduction** |

*Note: Benchmarks recorded on single-node test environment. Production performance scales linearly across available CPU cores via `SO_REUSEPORT` worker pools.*

---

## 🛡️ Core Capabilities

- **Zero-GC Predictability**: Built on Tokio multi-thread runtime with strict asynchronous socket multiplexing.
- **Full Protocol Coverage**:
  - Classic **UDP & TCP** (RFC 1035) with sharded worker threads.
  - **DoT** (DNS over TLS - RFC 7858) via `tokio-rustls`.
  - **DoH** (DNS over HTTPS - RFC 8484) with HTTP/2 and CORS preflight.
  - **DoQ** (DNS over QUIC - RFC 9250) via `quinn` for zero round-trip connection resumption.
- **Sharded Lock-Free Cache**: Concurrent LRU caching with lock sharding to prevent lock contention under 10k+ concurrent clients.
- **O(1) Threat Filtering**: Sub-microsecond Bloom filter matching against millions of malicious domains.
- **Active Defense Integration**: Native bidirectional sync with shield gateways (e.g., [Tameng](https://github.com/koodoxz/tameng)) for real-time threat intelligence feeds.
- **Heuristic Threat Detection**:
  - **DGA Engine**: Entropy and n-gram scoring for algorithmic domain generation attacks.
  - **DNS Tunneling Sentinel**: Rate and subdomain entropy anomaly detection.

---

## 🚀 Quick Start

### 1. Requirements & Build
* **Recommended OS**: Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+) with Kernel 5.15+ (optimal for `SO_REUSEPORT` and eBPF/XDP).
* **Compiler**: Rust 1.75+ (`cargo`).
* *Windows Developer Note*: If building on Windows MSVC, ensure `nasm` is installed on `PATH` for cryptographic assemblies, or build via WSL2 / Docker.

```bash
# Clone repository
git clone https://github.com/koodoxz/runut.git
cd runut

# Compile release binary
cargo build --release
```

### 2. Run Standalone
```bash
# Run with default configuration
sudo ./target/release/runut --config configs/runut.yaml

# Or execute with CLI arguments
sudo ./target/release/runut --listen 0.0.0.0:53 --upstream 1.1.1.1:53
```

### 3. Run with Docker
```bash
docker build -t runut .
docker run -d --name runut-dns -p 53:53/udp -p 53:53/tcp runut
```

---

## ⚙️ Configuration Architecture

The complete configuration is governed by a declarative YAML file (`configs/runut.yaml`):

```yaml
listen:
  udp: "0.0.0.0:53"
  tcp: "0.0.0.0:53"
  dot: "0.0.0.0:853"   # DNS over TLS
  doh: "0.0.0.0:443"   # DNS over HTTPS
  doq: "0.0.0.0:853"   # DNS over QUIC

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

tameng:
  enabled: true
  url: "https://your-shield-instance.example.com"
  api_key: "${TAMENG_API_KEY}"
```

---

## 🗺️ Project Status & Roadmap

- [x] High-performance UDP / TCP async multiplexing
- [x] Sharded LRU cache with TTL auto-expiration
- [x] Encrypted transport (DoT, DoH, DoQ)
- [x] Sovereign Code Hunter safety verification (Zero naked panics in worker loop)
- [ ] Automated eBPF/XDP kernel bypass kernel driver packaging
- [ ] Dynamic Kubernetes sidecar deployment helm chart

---

## 📄 License & Intellectual Property

Licensed under the [MIT License](LICENSE). Open for community contributions and enterprise adoption.
