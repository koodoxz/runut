# MIMIR-XDP: Kernel-Bypass DNS Accelerator

## 🔥 Performance Target

| Mode | Expected QPS | Latency |
|------|-------------|---------|
| Userspace (current) | ~37K | ~2.5ms |
| **XDP (kernel-bypass)** | **100K-500K** | **<50µs** |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Network Interface                        │
│                         (eth0)                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    XDP Program (eBPF)                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Parse DNS   │───▶│ Cache Lookup│───▶│ Build Reply │     │
│  │ Query       │    │ (LRU Map)   │    │ (if hit)    │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                              │                              │
│                    ┌─────────┴─────────┐                   │
│                    │                   │                    │
│              Cache HIT           Cache MISS                 │
│                    │                   │                    │
│                    ▼                   ▼                    │
│               XDP_TX              XDP_PASS                  │
│            (respond!)        (to userspace)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (cache misses only)
┌─────────────────────────────────────────────────────────────┐
│                    MIMIR-RS (Userspace)                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Full DNS    │───▶│ Query       │───▶│ Update XDP  │     │
│  │ Processing  │    │ Upstream    │    │ Cache       │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. eBPF Program (`mimir-xdp-ebpf`)
- Runs in kernel at NIC driver level
- Parses UDP DNS queries
- Looks up domain hash in LRU cache
- Returns XDP_TX for hits (respond directly)
- Returns XDP_PASS for misses (userspace)

### 2. Userspace Loader (`mimir-xdp`)
- Loads eBPF program onto interface
- Syncs cache from MIMIR-RS
- Monitors XDP statistics

### 3. MIMIR-RS Integration
- Handles cache misses
- Populates XDP cache via UDP sync
- Full DoT/DoH/DoQ support

## Building

```bash
# Install dependencies
sudo apt install clang llvm libelf-dev

# Install bpf-linker
cargo install bpf-linker

# Build
./build.sh
```

## Usage

```bash
# Start XDP accelerator (as root)
sudo ./mimir-xdp --interface eth0 --mode native

# In another terminal, start MIMIR-RS
sudo ./mimir --listen 0.0.0.0:53 --xdp-sync 127.0.0.1:9154
```

## XDP Modes

| Mode | Description | Performance |
|------|-------------|-------------|
| `native` | Driver-level XDP | Best (if supported) |
| `skb` | Generic/SKB mode | Good (always works) |
| `hw` | Hardware offload | Extreme (NIC specific) |

## Statistics

The XDP program tracks:
- `XDP_PASS` - Packets passed to userspace
- `XDP_TX` - Packets responded from XDP
- `DNS_QUERIES` - Total DNS queries seen
- `CACHE_HITS` - Queries answered from XDP cache
- `CACHE_MISSES` - Queries forwarded to userspace

## Safety Notes

1. XDP runs in kernel - bugs can crash system
2. Always test in `skb` mode first
3. Use `native` only on production after testing
4. Never use `hw` unless NIC specifically supports it
