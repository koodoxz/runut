//! RUNUT-XDP Userspace Loader v0.3
//!
//! Features:
//! - Loads XDP program onto network interface
//! - UDP Sync Server (port 9154) to receive cache from RUNUT
//! - Real-time statistics monitoring
//! - Full cache population in eBPF maps

use anyhow::{Context, Result};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, Pod};
use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::signal;
use tracing::{info, warn, Level};

/// DNS response entry (must match eBPF struct)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct DnsResponse {
    ip_addr: u32,
    ttl: u32,
}

unsafe impl Pod for DnsResponse {}

// Stats keys (must match eBPF)
const STAT_PACKETS_TOTAL: u32 = 0;
const STAT_CFG_ENABLE_TX: u32 = 1;
const STAT_DNS_QUERIES: u32 = 2;
const STAT_CACHE_HITS: u32 = 3;
const STAT_CACHE_MISSES: u32 = 4;
const STAT_XDP_TX: u32 = 5;
const STAT_LAST_HASH_LOW: u32 = 10;
const STAT_LAST_HASH_HIGH: u32 = 11;
const STAT_LAST_QNAME_LEN: u32 = 12;

#[derive(Parser, Debug)]
#[command(name = "runut-xdp")]
#[command(version = "0.3.0")]
#[command(about = "Ultra-fast XDP DNS accelerator for RUNUT")]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    interface: String,
    
    #[arg(short, long, default_value = "skb")]
    mode: String,
    
    #[arg(short, long, default_value = "../target/bpfel-unknown-none/release/runut-xdp-ebpf")]
    ebpf: String,
    
    #[arg(short, long, default_value = "127.0.0.1:9154")]
    sync_addr: String,
    
    #[arg(short, long, default_value = "3")]
    stats_interval: u64,
    
    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    enable_tx: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    let log_level = if args.verbose { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt().with_max_level(log_level).compact().init();
    
    print_banner();
    
    info!("🚀 Loading RUNUT-XDP v0.3...");
    
    let ebpf_data = std::fs::read(&args.ebpf).context("Failed to read eBPF object file")?;
    let mut ebpf = Ebpf::load(&ebpf_data).context("Failed to load eBPF program")?;
    
    
    let program: &mut Xdp = ebpf.program_mut("runut_xdp").context("XDP program not found")?.try_into()?;
    program.load()?;
    
    // Use direct assignment instead of UPDATE_IF_NOEXIST to improve compatibility
    // with virtualized environments (virtio_net on KVM)
    let flags = match args.mode.as_str() {
        "skb" => XdpFlags::SKB_MODE,
        "drv" | "native" => XdpFlags::DRV_MODE,
        "hw" => XdpFlags::HW_MODE,
        _ => XdpFlags::SKB_MODE,  // Default to Generic XDP
    };
    
    program.attach(&args.interface, flags).context("Failed to attach XDP")?;
    info!("✅ Attached XDP to {} ({})", args.interface, args.mode);


    if let Some(stats) = ebpf.map_mut("STATS") {
        if let Ok(mut stats_map) = HashMap::<_, u32, u64>::try_from(stats) {
            let val: u64 = if args.enable_tx { 1 } else { 0 };
            stats_map.insert(&STAT_CFG_ENABLE_TX, &val, 0)?;
            info!("XDP_TX enabled: {}", args.enable_tx);
        }
    }

    // Pre-populate high-intensity test entry
    if let Some(cache) = ebpf.map_mut("DNS_CACHE") {
        if let Ok(mut cache_map) = HashMap::<_, u64, DnsResponse>::try_from(cache) {
            let name = "perf.test.com";
            let hash = compute_loader_hash(name);
            let resp = DnsResponse { ip_addr: u32::from_be_bytes([1, 2, 3, 4]), ttl: 60 };
            cache_map.insert(&hash, &resp, 0)?;
            info!("🎯 Pre-populated: {} -> 1.2.3.4 (hash={})", name, hash);
        }
    }

    // Sync Server Setup
    let sync_addr: SocketAddr = args.sync_addr.parse()?;
    let socket = UdpSocket::bind(sync_addr).await?;
    info!("📡 Cache Sync Server listening on {}", sync_addr);

    // Stats variables
    let stats_interval = Duration::from_secs(args.stats_interval);
    let mut prev_queries: u64 = 0;
    let mut prev_time = std::time::Instant::now();
    
    // Main loop
    let mut buf = [0u8; 1024];
    
    loop {
        tokio::select! {
            // Stats Reporting
            _ = tokio::time::sleep(stats_interval) => {
                if let Ok(stats_map) = HashMap::<_, u32, u64>::try_from(ebpf.map("STATS").unwrap()) {
                    let total = stats_map.get(&STAT_PACKETS_TOTAL, 0).unwrap_or(0);
                    let queries = stats_map.get(&STAT_DNS_QUERIES, 0).unwrap_or(0);
                    let hits = stats_map.get(&STAT_CACHE_HITS, 0).unwrap_or(0);
                    let tx = stats_map.get(&STAT_XDP_TX, 0).unwrap_or(0);
                    let enable_tx = stats_map.get(&STAT_CFG_ENABLE_TX, 0).unwrap_or(0);
                    
                    // Debug: read eBPF computed hash
                    let hash_lo = stats_map.get(&STAT_LAST_HASH_LOW, 0).unwrap_or(0);
                    let hash_hi = stats_map.get(&STAT_LAST_HASH_HIGH, 0).unwrap_or(0);
                    let ebpf_hash = (hash_hi << 32) | hash_lo;
                    let qlen = stats_map.get(&STAT_LAST_QNAME_LEN, 0).unwrap_or(0);
                    
                    let elapsed = prev_time.elapsed().as_secs_f64();
                    let qps = if elapsed > 0.0 { ((queries - prev_queries) as f64 / elapsed) as u64 } else { 0 };
                    let hit_rate = if queries > 0 { (hits as f64 / queries as f64) * 100.0 } else { 0.0 };
                    
                    info!("📊 XDP: total={} dns={} qps={} hits={} ({:.1}%) tx={} enable_tx={} | last_hash={} qlen={}", total, queries, qps, hits, hit_rate, tx, enable_tx, ebpf_hash, qlen);
                    prev_queries = queries;
                    prev_time = std::time::Instant::now();
                }
            }
            
            // Sync Packet Handling
            Ok((len, _)) = socket.recv_from(&mut buf) => {
                // Packet format: [hash:8][ip:4][ttl:4]
                if len >= 16 {
                    let hash = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                    // FIX: IP comes from network in big-endian (network byte order)
                    let ip = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                    let ttl = u32::from_le_bytes(buf[12..16].try_into().unwrap());
                    
                    if let Ok(mut cache_map) = HashMap::<_, u64, DnsResponse>::try_from(ebpf.map_mut("DNS_CACHE").unwrap()) {
                        let resp = DnsResponse { ip_addr: ip, ttl };
                        if let Err(e) = cache_map.insert(&hash, &resp, 0) {
                            warn!("❌ Failed to sync cache: {}", e);
                        } else {
                            if args.verbose { info!("📦 Synced: hash={}, ip={:08x}, ttl={}", hash, ip, ttl); }
                        }
                    }
                }
            }
            
            _ = signal::ctrl_c() => {
                info!("Stopping RUNUT-XDP...");
                break;
            }
        }
    }
    
    Ok(())
}

fn compute_loader_hash(query_name: &str) -> u64 {
    let mut wire = Vec::with_capacity(query_name.len() + 2);
    for label in query_name.split('.').filter(|s| !s.is_empty()) {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);

    let mut hash: u64 = 0;
    for (i, &byte) in wire.iter().enumerate() {
        if i >= 64 {
            break;
        }
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        if byte == 0 {
            break;
        }
    }
    hash
}

fn print_banner() {
    println!(r#"
 ███╗   ███╗██╗███╗   ███╗██╗██████╗       ██╗  ██╗██████╗ ██████╗ 
 ████╗ ████║██║████╗ ████║██║██╔══██╗      ╚██╗██╔╝██╔══██╗██╔══██╗
 ██╔████╔██║██║██╔████╔██║██║██████╔╝█████╗ ╚███╔╝ ██║  ██║██████╔╝
 ██║╚██╔╝██║██║██║╚██╔╝██║██║██╔══██╗╚════╝ ██╔██╗ ██║  ██║██╔═══╝ 
 ██║ ╚═╝ ██║██║██║ ╚═╝ ██║██║██║  ██║      ██╔╝ ██╗██████╔╝██║     
 ╚═╝     ╚═╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚═════╝ ╚═╝     
                                                                    
              Kernel-Bypass DNS Accelerator [XDP/eBPF]
                       Runut v0.3
    "#);
}
