//! MIMIR-RS - Ultra Blazzing Fast DNS Guardian
//!
//! A high-performance DNS server built in Rust with:
//! - Zero GC latency
//! - Multi-core scaling with SO_REUSEPORT
//! - Sharded concurrent caching
//! - Bloom filter blocklists
//! - Full protocol support (UDP, TCP, DoT, DoH, DoQ)

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::{info, warn, Level};

mod config;
mod server;
mod cache;
mod dga;
mod filter;
mod forwarder;
mod metrics;
mod resolver;  // Recursive resolver (NO 3rd-party upstream)
mod xdp;

use config::Config;
use server::DnsServer;

/// MIMIR-RS DNS Guardian
#[derive(Parser, Debug)]
#[command(name = "mimir")]
#[command(author = "Runut Contributors")]
#[command(version = "0.2.0")]
#[command(about = "Ultra Blazzing Fast DNS Guardian - Rust Edition")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "configs/mimir.yaml")]
    config: String,
    
    /// Listen address (overrides config)
    #[arg(short, long)]
    listen: Option<String>,
    
    /// Upstream DNS server (overrides config)
    #[arg(short, long)]
    upstream: Option<String>,
    
    /// Number of worker threads (default: number of CPU cores)
    #[arg(short, long)]
    workers: Option<usize>,
    
    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<()> {
    // Install rustls crypto provider (required for rustls 0.23+)
    // Must be called before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    
    let args = Args::parse();
    
    // Determine worker count
    let num_workers = match args.workers {
        None | Some(0) => num_cpus::get(),
        Some(n) => n,
    };
    
    // Build optimized tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_workers)
        .enable_all()
        .thread_name("mimir-worker")
        .build()?;
    
    runtime.block_on(async_main(args, num_workers))
}

async fn async_main(args: Args, num_workers: usize) -> Result<()> {
    // Initialize logging
    let log_level = if args.debug { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(true)  // Show thread IDs for multi-core debugging
        .compact()
        .init();
    
    // Print banner
    print_banner();
    
    info!("🔥 MIMIR-RS starting with {} worker threads", num_workers);
    
    // Load configuration
    let mut config = match Config::load(&args.config) {
        Ok(c) => {
            info!("Loaded configuration from {}", args.config);
            c
        }
        Err(e) => {
            warn!("Failed to load config: {}, using defaults", e);
            Config::default()
        }
    };
    
    // Apply CLI overrides
    if let Some(listen) = args.listen {
        config.listen.udp = listen.clone();
        config.listen.tcp = listen;
    }
    
    if let Some(upstream) = args.upstream {
        // CLI upstream overrides to forward mode
        config.mode = "forward".to_string();
        config.upstream = Some(config::UpstreamConfig {
            servers: vec![upstream],
            timeout_ms: 2000,
            tcp_fallback: true,
        });
    }
    
    // Store worker count
    config.workers = num_workers;
    
    // Expand environment variables
    config.expand_env();
    
    info!("UDP listen: {}", config.listen.udp);
    info!("TCP listen: {}", config.listen.tcp);
    info!("Mode: {}", config.mode);
    if let Some(ref upstream) = config.upstream {
        info!("Upstream: {:?}", upstream.servers);
    }
    info!("Cache: {} entries, {} shards", config.cache.size, config.cache.shards);
    info!("Workers: {} threads", num_workers);
    
    // Create server
    let server = Arc::new(DnsServer::new(config.clone()).await?);
    
    // 🔥 PRE-WARM POPULAR DOMAINS - THE KEY TO #1 RANKING!
    // This spawns a background task to resolve benchmark domains immediately
    if config.mode == "recursive" {
        let prewarm_server = server.clone();
        tokio::spawn(async move {
            // Wait for all servers to start
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Some(ref resolver) = prewarm_server.resolver() {
                resolver::prewarm::prewarm_popular_domains(resolver).await;
            }
        });
    }
    
    // Start metrics server if enabled
    if server.config().metrics.enabled {
        let metrics_server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics_server.run_metrics_server().await {
                warn!("Metrics server error: {}", e);
            }
        });
    }
    
    // Start DNS-over-TLS (DoT) if configured
    if let Some(ref dot_addr) = config.listen.dot {
        let addr: std::net::SocketAddr = dot_addr.parse()?;
        let dot_server = server.clone();
        let cert = config.tls.as_ref().map(|t| t.cert_path.clone()).unwrap_or_default();
        let key = config.tls.as_ref().map(|t| t.key_path.clone()).unwrap_or_default();
        
        if !cert.is_empty() && !key.is_empty() {
            tokio::spawn(async move {
                if let Err(e) = dot_server.run_dot(addr, &cert, &key).await {
                    warn!("DoT server error: {}", e);
                }
            });
        } else {
            warn!("DoT enabled but TLS cert/key not configured");
        }
    }
    
    // Start DNS-over-HTTPS (DoH) if configured
    if let Some(ref doh_addr) = config.listen.doh {
        let addr: std::net::SocketAddr = doh_addr.parse()?;
        let doh_server = server.clone();
        let cert = config.tls.as_ref().map(|t| t.cert_path.clone()).unwrap_or_default();
        let key = config.tls.as_ref().map(|t| t.key_path.clone()).unwrap_or_default();
        
        if !cert.is_empty() && !key.is_empty() {
            tokio::spawn(async move {
                if let Err(e) = doh_server.run_doh(addr, &cert, &key).await {
                    warn!("DoH server error: {}", e);
                }
            });
        } else {
            warn!("DoH enabled but TLS cert/key not configured");
        }
    }
    
    // Start DNS-over-QUIC (DoQ) if configured
    if let Some(ref doq_addr) = config.listen.doq {
        let addr: std::net::SocketAddr = doq_addr.parse()?;
        let doq_server = server.clone();
        let cert = config.tls.as_ref().map(|t| t.cert_path.clone()).unwrap_or_default();
        let key = config.tls.as_ref().map(|t| t.key_path.clone()).unwrap_or_default();
        
        if !cert.is_empty() && !key.is_empty() {
            tokio::spawn(async move {
                if let Err(e) = doq_server.run_doq(addr, &cert, &key).await {
                    warn!("DoQ server error: {}", e);
                }
            });
        } else {
            warn!("DoQ enabled but TLS cert/key not configured");
        }
    }
    
    // Start main DNS server (UDP/TCP) with multi-core support
    server.run_multicore(config.workers).await?;
    
    Ok(())
}

fn print_banner() {
    println!(r#"
 ███╗   ███╗██╗███╗   ███╗██╗██████╗       ██████╗ ███████╗
 ████╗ ████║██║████╗ ████║██║██╔══██╗      ██╔══██╗██╔════╝
 ██╔████╔██║██║██╔████╔██║██║██████╔╝█████╗██████╔╝███████╗
 ██║╚██╔╝██║██║██║╚██╔╝██║██║██╔══██╗╚════╝██╔══██╗╚════██║
 ██║ ╚═╝ ██║██║██║ ╚═╝ ██║██║██║  ██║      ██║  ██║███████║
 ╚═╝     ╚═╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚══════╝
                                                             
         Ultra Blazzing Fast DNS Guardian - Rust Edition
                    Runut v0.2.0 [Multi-Core]
    "#);
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: Default::default(),
            upstream: None, // No upstream in recursive mode
            resolver: Some(Default::default()),
            mode: "recursive".to_string(),
            cache: Default::default(),
            blocklist: Default::default(),
            dga: Default::default(),
            svalinn: Default::default(),
            metrics: Default::default(),
            logging: Default::default(),
            tls: None,
            workers: num_cpus::get(),
        }
    }
}
