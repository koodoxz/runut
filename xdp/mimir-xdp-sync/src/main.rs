//! MIMIR-XDP Sync Bridge
//! 
//! Lightweight sync bridge that connects to an existing DNS_CACHE eBPF map
//! (loaded by an external XDP loader) and updates it with DNS cache entries from MIMIR-RS.
//! 
//! This fixes the byte-order bug in the Go xdp-sync-v5 version.

use aya::maps::{HashMap, Map, MapData};
use clap::Parser;
use std::os::fd::FromRawFd;
use tokio::net::UdpSocket;
use tracing::{info, warn};

#[repr(C)]
#[derive(Clone, Copy)]
struct DnsResponse {
    ip_addr: u32,
    ttl: u32,
}

unsafe impl aya::Pod for DnsResponse {}

#[derive(Parser, Debug)]
#[command(name = "mimir-xdp-sync")]
#[command(about = "Sync bridge for MIMIR XDP DNS cache")]
struct Args {
    /// eBPF map ID for DNS_CACHE
    #[arg(long)]
    map_id: u32,

    /// UDP address to listen for sync packets
    #[arg(long, default_value = "127.0.0.1:9154")]
    sync_addr: String,

    /// Stats interval in seconds
    #[arg(long, default_value = "30")]
    stats_interval: u64,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn get_map_fd_by_id(map_id: u32) -> Result<i32, std::io::Error> {
    #[repr(C)]
    #[derive(Default)]
    struct BpfAttr {
        map_id: u32,
        next_id: u32,
        open_flags: u32,
    }
    
    let mut attr = BpfAttr::default();
    attr.map_id = map_id;
    
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            0x1d_i32, // BPF_MAP_GET_FD_BY_ID
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttr>(),
        )
    };
    
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose { tracing::Level::DEBUG } else { tracing::Level::INFO })
        .compact()
        .init();

    println!(r#"
 ███╗   ███╗██╗███╗   ███╗██╗██████╗       ███████╗██╗   ██╗███╗   ██╗ ██████╗
 ████╗ ████║██║████╗ ████║██║██╔══██╗      ██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝
 ██╔████╔██║██║██╔████╔██║██║██████╔╝█████╗███████╗ ╚████╔╝ ██╔██╗ ██║██║     
 ██║╚██╔╝██║██║██║╚██╔╝██║██║██╔══██╗╚════╝╚════██║  ╚██╔╝  ██║╚██╗██║██║     
 ██║ ╚═╝ ██║██║██║ ╚═╝ ██║██║██║  ██║      ███████║   ██║   ██║ ╚████║╚██████╗
 ╚═╝     ╚═╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═╝      ╚══════╝   ╚═╝   ╚═╝  ╚═══╝ ╚═════╝
                    XDP DNS Cache Sync Bridge v1.0 (Rust)
"#);

    info!("📦 Connecting to DNS_CACHE map ID: {}", args.map_id);
    
    // Get map FD by ID using BPF syscall
    let map_fd = get_map_fd_by_id(args.map_id)?;
    info!("✅ Got map FD: {}", map_fd);
    
    // Create MapData from the raw FD, then wrap in Map for HashMap conversion
    let map_data = unsafe { MapData::from_fd(std::os::fd::OwnedFd::from_raw_fd(map_fd)) }?;
    let map = Map::HashMap(map_data);
    let mut cache_map: HashMap<_, u64, DnsResponse> = HashMap::try_from(map)?;
    
    info!("✅ Connected to DNS_CACHE map");
    
    // Bind UDP socket
    let socket = UdpSocket::bind(&args.sync_addr).await?;
    info!("🔗 Listening on: {}", args.sync_addr);
    info!("🎯 Ready to sync DNS cache entries...\n");

    let mut buf = [0u8; 64];
    let mut sync_count: u64 = 0;
    let mut last_stats = std::time::Instant::now();
    let stats_interval = std::time::Duration::from_secs(args.stats_interval);

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, _src)) => {
                        if len >= 16 {
                            let hash = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                            // CRITICAL FIX: IP comes from network in big-endian
                            let ip = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                            let ttl = u32::from_le_bytes(buf[12..16].try_into().unwrap());

                            let resp = DnsResponse { ip_addr: ip, ttl };

                            if cache_map.insert(&hash, &resp, 0).is_ok() {
                                sync_count += 1;
                                if args.verbose {
                                    let ip_bytes = ip.to_be_bytes();
                                    info!("📦 Synced: hash={} ip={}.{}.{}.{} ttl={}",
                                        hash, ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], ttl);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("❌ Socket error: {}", e);
                    }
                }
            }
            
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                if last_stats.elapsed() >= stats_interval {
                    info!("📊 Synced {} entries in last {}s", sync_count, args.stats_interval);
                    sync_count = 0;
                    last_stats = std::time::Instant::now();
                }
            }
        }
    }
}
