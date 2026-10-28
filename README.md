# Runut (RUNUT) ᛘᛁᛘᛁᚾᚾ

> **High-Performance Autonomous DNS Guardian — Engineered in Rust**  
> Sub-millisecond latency, zero garbage collection, multi-protocol resolution, and real-time active threat defense.

[![Rust](https://img.shields.io/badge/Rust-1.75+-000000?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Protocols](https://img.shields.io/badge/Protocols-UDP%20%7C%20TCP%20%7C%20DoT%20%7C%20DoH%20%7C%20DoQ-green.svg)](#architecture--modes)

---

## Executive Summary

**Runut** (Indonesian: *"to trace / track systematically"*) is a high-performance DNS resolver and security gateway built in pure Rust. It is engineered to replace legacy DNS servers with a zero-cost abstraction stack that eliminates GC pauses and withstands high-QPS network stress.

### Benchmarks (Directional Baseline)
| Metric | Go Reference Implementation | Runut (Rust) | Delta |
| :--- | :--- | :--- | :--- |
| **Throughput** | ~5,000 QPS | **20,000+ QPS** | **4x Faster** |
| **Median Latency** | 0.69 ms | **0.20 ms** | **3.5x Lower** |
| **P99 Latency** | ~8.00 ms | **< 1.00 ms** | **8x Predictability** |
| **Memory Footprint** | ~81 MB | **< 30 MB** | **63% Reduction** |

*Note: Benchmarks recorded on single-node test environment. Production performance scales linearly across available CPU cores via `SO_REUSEPORT` worker pools.*

---

## The Defense Ecosystem

Runut operates as the core resolution brain within a unified, defense-in-depth security infrastructure:

```
[ Client / Edge Devices ]
           │
           ▼ (Plaintext DNS on localhost)
   ┌──────────────┐
   │    Caraka    │  Lightweight DNS over QUIC (DoQ) Edge Forwarder
   └──────┬───────┘
          │ (Encrypted DoQ / QUIC - Port 8853)
          ▼
   ┌──────────────┐   eBPF / XDP Kernel Sentry
   │    Gapura    │◄───[ Kalas ] (Layer 3 & Layer 4 Anti-DDoS Filter)
   └──────┬───────┘   Public Ingress Gateway (Rate-Limiting & TLS Termination)
          │
          │ (Internal Private Wire)
          ▼
   ┌──────────────┐   Real-Time Threat Feeds
   │    Runut     │◄─────────────────────────► [ Tameng ]
   └──────┬───────┘   Authoritative Root DNS   Autonomous L7 WAF
          │
          ▼ (Direct iterative queries)
[ 13 Internet Root Servers (A.ROOT .. M.ROOT) ]
```

| Component | Layer / Scope | Role in Ecosystem |
| :--- | :--- | :--- |
| **[Tameng](https://github.com/koodoxz/tameng)** | Layer 7 (Application) | Autonomous Web Application Firewall, Behavioral Defense, and Threat Intelligence Hub |
| **[Runut](https://github.com/koodoxz/runut)** | Layer 7 (DNS Core) | High-Performance Zero-GC Recursive Root Resolver and DGA/Tunneling Sentinel |
| **Gapura** *(Coming Soon)* | Ingress Gateway | Public entry portal terminating DoH, DoT, and DoQ with token-bucket rate limiting |
| **Kalas** *(Coming Soon)* | Layer 3 & 4 (Kernel) | eBPF/XDP sentinel dropping packet floods (SYN flood, port scans) at wire speed |
| **Caraka** *(Coming Soon)* | Client / Edge | Zero-round-trip local proxy forwarding endpoint queries over encrypted QUIC |

---

## Core Capabilities

- **Dual-Engine Resolution**:
  - **Recursive Root Resolver**: Resolves directly from authoritative Internet Root Servers (`A.ROOT-SERVERS.NET` through `M.ROOT-SERVERS.NET`) with built-in NS-cache and socket pooling.
  - **Forwarding Gateway**: Low-latency proxying to upstream DNS providers with round-robin health-checking.
- **Zero-GC Predictability**: Built on Tokio multi-thread runtime with strict asynchronous socket multiplexing.
- **Full Protocol Coverage**:
  - Classic **UDP & TCP** (RFC 1035) with sharded worker threads.
  - **DoT** (DNS over TLS - RFC 7858) via `tokio-rustls`.
  - **DoH** (DNS over HTTPS - RFC 8484) with HTTP/2 and CORS preflight.
  - **DoQ** (DNS over QUIC - RFC 9250) via `quinn` for zero round-trip connection resumption.
- **Sharded Lock-Free Cache**: Concurrent LRU caching with lock sharding to prevent lock contention under 10k+ concurrent clients.
- **Sub-Microsecond Filtering**: Bloom filter matching against millions of malicious domains.
- **Active Defense Integration**: Native bidirectional sync with shield gateways (e.g., [Tameng](https://github.com/koodoxz/tameng)) for real-time threat intelligence feeds.
- **Heuristic Threat Detection**:
  - **DGA Engine**: Entropy and n-gram scoring for algorithmic domain generation attacks.
  - **DNS Tunneling Sentinel**: Rate and subdomain entropy anomaly detection.

---

## Architecture & Modes

Runut supports two operational modes defined in `configs/runut.yaml`:

### 1. Full Recursive Root Mode (Default)
In this mode, Runut acts as a **true authoritative recursive resolver** without depending on any external upstream resolvers (Google, Cloudflare, Quad9). It queries the 13 Root hints, follows TLD delegations, and caches nameserver authoritative responses directly:
```yaml
mode: recursive

resolver:
  timeout_ms: 5000
  max_retries: 3
  max_depth: 30
  pool_size: 50
```

### 2. Forwarding Mode (Optional)
If your infrastructure requires routing through dedicated upstream DNS providers or corporate resolvers:
```yaml
mode: forward

upstream:
  servers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  timeout_ms: 2000
  tcp_fallback: true
```

---

## Quick Start

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
# Run with default recursive configuration
sudo ./target/release/runut --config configs/runut.yaml

# Or execute with CLI arguments
sudo ./target/release/runut --listen 0.0.0.0:53
```

### 3. Run with Docker
```bash
docker build -t runut .
docker run -d --name runut-dns -p 53:53/udp -p 53:53/tcp runut
```

---

## Configuration Reference

The complete configuration is governed by `configs/runut.yaml`:

```yaml
listen:
  udp: "0.0.0.0:53"
  tcp: "0.0.0.0:53"
  dot: "0.0.0.0:853"   # DNS over TLS
  doh: "0.0.0.0:443"   # DNS over HTTPS
  doq: "0.0.0.0:853"   # DNS over QUIC

# Resolution mode: "recursive" (authoritative from root) or "forward"
mode: recursive

resolver:
  timeout_ms: 5000
  max_retries: 3
  max_depth: 30
  pool_size: 50

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

## Project Status & Roadmap

The current version focuses on core resolution stability and cryptographic protocol hardening:

- [x] High-performance UDP / TCP async multiplexing
- [x] Recursive Root Resolver with NS cache & connection pooling
- [x] Sharded LRU cache with TTL auto-expiration
- [x] Encrypted transport (DoT, DoH, DoQ)
- [x] Sovereign Code Hunter safety verification (Zero naked panics in worker loop)
- [ ] Automated eBPF/XDP kernel bypass driver packaging
- [ ] Dynamic Kubernetes sidecar deployment helm chart

---

## License & Intellectual Property

Licensed under the **GNU Affero General Public License v3.0 or later ([AGPL-3.0-or-later](LICENSE))**. Open for community contributions, with source-sharing requirements for network-deployed service modifications.
