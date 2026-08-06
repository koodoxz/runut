//! DNS Server Module
//!
//! Handles UDP, TCP, DoT, DoH, and DoQ DNS listeners with async processing.

pub mod dot;  // DNS-over-TLS
pub mod doh;  // DNS-over-HTTPS
pub mod doq;  // DNS-over-QUIC

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::config::Config;
use crate::cache::DnsCache;
use crate::dga;
use crate::filter::BlockFilter;
use crate::forwarder::DnsForwarder;
use crate::resolver::{Resolver, ResolverConfig};
use crate::xdp::XdpSyncClient;

/// Resolution backend
enum ResolutionBackend {
    /// Forward to upstream servers (1.1.1.1, 8.8.8.8, etc.)
    Forwarder(Arc<DnsForwarder>),
    /// Recursive resolution from root servers
    Recursive(Arc<Resolver>),
}

/// Main DNS Server
pub struct DnsServer {
    config: Config,
    cache: Arc<DnsCache>,
    filter: Arc<BlockFilter>,
    backend: ResolutionBackend,
    stats: Arc<ServerStats>,
    xdp_sync: Option<Arc<XdpSyncClient>>,
    // Bounds both the memory an attacker-controlled stream of distinct DGA
    // labels can consume and the volume of `warn!` lines a single repeated
    // label can generate -- without this, MIMIR-DGA-DETECT-001's alert path
    // is an unrate-limited log/disk-fill vector (found in review). Fixed
    // capacity, not time-windowed: an evicted-then-reseen label just
    // re-alerts, an accepted imprecision favoring a hard memory bound.
    dga_alert_seen: parking_lot::Mutex<lru::LruCache<String, ()>>,
}

/// Server statistics
pub struct ServerStats {
    pub queries_total: std::sync::atomic::AtomicU64,
    pub queries_cached: std::sync::atomic::AtomicU64,
    pub queries_blocked: std::sync::atomic::AtomicU64,
    pub queries_forwarded: std::sync::atomic::AtomicU64,
    pub queries_failed: std::sync::atomic::AtomicU64,
    pub queries_dga_suspected: std::sync::atomic::AtomicU64,
    // Latency buckets for histogram (in microseconds): [0-1ms, 1-5ms, 5-10ms, 10-50ms, 50-100ms, 100ms+]
    pub latency_bucket_0_1ms: std::sync::atomic::AtomicU64,
    pub latency_bucket_1_5ms: std::sync::atomic::AtomicU64,
    pub latency_bucket_5_10ms: std::sync::atomic::AtomicU64,
    pub latency_bucket_10_50ms: std::sync::atomic::AtomicU64,
    pub latency_bucket_50_100ms: std::sync::atomic::AtomicU64,
    pub latency_bucket_100ms_plus: std::sync::atomic::AtomicU64,
    pub latency_sum_micros: std::sync::atomic::AtomicU64,
}

impl ServerStats {
    pub fn new() -> Self {
        Self {
            queries_total: std::sync::atomic::AtomicU64::new(0),
            queries_cached: std::sync::atomic::AtomicU64::new(0),
            queries_blocked: std::sync::atomic::AtomicU64::new(0),
            queries_forwarded: std::sync::atomic::AtomicU64::new(0),
            queries_failed: std::sync::atomic::AtomicU64::new(0),
            queries_dga_suspected: std::sync::atomic::AtomicU64::new(0),
            latency_bucket_0_1ms: std::sync::atomic::AtomicU64::new(0),
            latency_bucket_1_5ms: std::sync::atomic::AtomicU64::new(0),
            latency_bucket_5_10ms: std::sync::atomic::AtomicU64::new(0),
            latency_bucket_10_50ms: std::sync::atomic::AtomicU64::new(0),
            latency_bucket_50_100ms: std::sync::atomic::AtomicU64::new(0),
            latency_bucket_100ms_plus: std::sync::atomic::AtomicU64::new(0),
            latency_sum_micros: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    pub fn inc_total(&self) {
        self.queries_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn inc_cached(&self) {
        self.queries_cached.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn inc_blocked(&self) {
        self.queries_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn inc_forwarded(&self) {
        self.queries_forwarded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn inc_failed(&self) {
        self.queries_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn inc_dga_suspected(&self) {
        self.queries_dga_suspected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    
    pub fn record_latency_micros(&self, micros: u64) {
        // Increment appropriate bucket
        if micros < 1000 {  // < 1ms
            self.latency_bucket_0_1ms.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if micros < 5000 {  // 1-5ms
            self.latency_bucket_1_5ms.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if micros < 10000 {  // 5-10ms
            self.latency_bucket_5_10ms.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if micros < 50000 {  // 10-50ms
            self.latency_bucket_10_50ms.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if micros < 100000 {  // 50-100ms
            self.latency_bucket_50_100ms.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {  // 100ms+
            self.latency_bucket_100ms_plus.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Track sum for calculating average
        self.latency_sum_micros.fetch_add(micros, std::sync::atomic::Ordering::Relaxed);
    }
}

impl DnsServer {
    /// Create new DNS server
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize cache
        let cache = Arc::new(DnsCache::new(
            config.cache.size,
            config.cache.shards,
        ));
        
        // Initialize filter
        let filter = Arc::new(BlockFilter::new(config.blocklist.bloom_size));
        
        // Initialize resolution backend based on mode
        let backend = match config.mode.as_str() {
            "forward" => {
                // Use upstream forwarder
                let upstream = config.upstream.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("upstream config required for forward mode"))?;
                let forwarder = Arc::new(DnsForwarder::new(
                    upstream.servers.clone(),
                    upstream.timeout_ms,
                ).await?);
                info!("Mode: FORWARD to {:?}", upstream.servers);
                ResolutionBackend::Forwarder(forwarder)
            }
            "recursive" | "core" | _ => {
                // Use recursive resolver (NO 3rd-party upstream!)
                let resolver_cfg = config.resolver.as_ref()
                    .map(|r| ResolverConfig {
                        timeout: std::time::Duration::from_millis(r.timeout_ms),
                        max_retries: r.max_retries,
                        max_depth: r.max_depth,
                        ipv6_enabled: r.ipv6_enabled,
                        pool_size: r.pool_size,
                    })
                    .unwrap_or_default();
                let resolver = Arc::new(Resolver::new(resolver_cfg));
                info!("Mode: RECURSIVE (NO 3rd-party upstream!)");
                ResolutionBackend::Recursive(resolver)
            }
        };
        
        // Load blocklist if enabled
        if config.blocklist.enabled && !config.blocklist.sources.is_empty() {
            info!("Loading blocklists...");
            for source in &config.blocklist.sources {
                if let Err(e) = filter.load_source(source).await {
                    warn!("Failed to load blocklist {}: {}", source, e);
                }
            }
            info!("Blocklist loaded: {} entries", filter.len());
        }
        
        let stats = Arc::new(ServerStats::new());
        
        let xdp_sync = XdpSyncClient::new("127.0.0.1:9154").map(Arc::new);
        if xdp_sync.is_some() {
            info!("XDP acceleration enabled (local sync on 127.0.0.1:9154)");
        }
        
        Ok(Self {
            config,
            cache,
            filter,
            backend,
            stats,
            xdp_sync,
            dga_alert_seen: parking_lot::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(10_000).unwrap(),
            )),
        })
    }
    
    /// Get config reference
    pub fn config(&self) -> &Config {
        &self.config
    }
    
    /// Get resolver reference (only available in recursive mode)
    pub fn resolver(&self) -> Option<&Arc<Resolver>> {
        match &self.backend {
            ResolutionBackend::Recursive(r) => Some(r),
            _ => None,
        }
    }
    
    /// Run DNS server (UDP and TCP) - single core mode
    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.run_multicore(1).await
    }
    
    /// Run DNS server with multi-core support using SO_REUSEPORT
    /// 
    /// This creates `num_workers` UDP sockets on the same port.
    /// The kernel load-balances incoming packets across all sockets,
    /// allowing true multi-core scaling without any application-level locking.
    pub async fn run_multicore(self: Arc<Self>, num_workers: usize) -> Result<()> {
        use socket2::{Domain, Protocol, Socket, Type};
        
        let udp_addr: SocketAddr = self.config.listen.udp.parse()?;
        let tcp_addr: SocketAddr = self.config.listen.tcp.parse()?;
        
        info!("🚀 Starting multi-core DNS server with {} UDP workers", num_workers);
        
        // Spawn multiple UDP listeners with SO_REUSEPORT
        let mut handles = Vec::new();
        
        for worker_id in 0..num_workers {
            let server = self.clone();
            let addr = udp_addr;
            
            let handle = tokio::spawn(async move {
                // Create socket with SO_REUSEPORT
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                    .expect("Failed to create socket");
                
                // Enable SO_REUSEADDR and SO_REUSEPORT
                socket.set_reuse_address(true).ok();
                #[cfg(unix)]
                socket.set_reuse_port(true).ok();
                
                // Set non-blocking and bind
                socket.set_nonblocking(true).ok();
                socket.bind(&addr.into()).expect("Failed to bind socket");
                
                // Convert to tokio UdpSocket
                let std_socket: std::net::UdpSocket = socket.into();
                let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket)
                    .expect("Failed to convert socket"));
                
                info!("UDP worker {} listening on {}", worker_id, addr);
                
                let mut buf = vec![0u8; 4096];
                
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, src)) => {
                            let query = bytes::Bytes::copy_from_slice(&buf[..len]);
                            let server = server.clone();
                            let socket = socket.clone();
                            
                            tokio::spawn(async move {
                                match server.handle_query(query).await {
                                    Ok(response) => {
                                        if let Err(e) = socket.send_to(&response, src).await {
                                            debug!("Send error to {}: {}", src, e);
                                        }
                                    }
                                    Err(e) => {
                                        debug!("Query error from {}: {}", src, e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("UDP recv error on worker {}: {}", worker_id, e);
                        }
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Start TCP listener (single, as TCP handles connections differently)
        let tcp_server = self.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = tcp_server.run_tcp(tcp_addr).await {
                error!("TCP server error: {}", e);
            }
        });
        handles.push(tcp_handle);
        
        info!("✅ All DNS workers started");
        
        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        info!("Shutdown signal received");
        
        for handle in handles {
            handle.abort();
        }
        
        Ok(())
    }
    
    /// Run UDP DNS server
    async fn run_udp(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("UDP DNS server listening on {}", addr);
        
        let mut buf = vec![0u8; 4096];
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let query = Bytes::copy_from_slice(&buf[..len]);
                    let server = self.clone();
                    let socket = socket.clone();
                    
                    tokio::spawn(async move {
                        match server.handle_query(query).await {
                            Ok(response) => {
                                if let Err(e) = socket.send_to(&response, src).await {
                                    debug!("Send error to {}: {}", src, e);
                                }
                            }
                            Err(e) => {
                                debug!("Query error from {}: {}", src, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("UDP recv error: {}", e);
                }
            }
        }
    }
    
    /// Run TCP DNS server
    async fn run_tcp(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("TCP DNS server listening on {}", addr);
        
        loop {
            let (mut stream, src) = listener.accept().await?;
            let server = self.clone();
            
            tokio::spawn(async move {
                // Read length prefix (2 bytes)
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                
                // Read DNS message
                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                
                match server.handle_query(Bytes::from(buf)).await {
                    Ok(response) => {
                        // Write length prefix + response
                        let len = (response.len() as u16).to_be_bytes();
                        let _ = stream.write_all(&len).await;
                        let _ = stream.write_all(&response).await;
                    }
                    Err(e) => {
                        debug!("TCP query error from {}: {}", src, e);
                    }
                }
            });
        }
    }
    
    /// Handle DNS query
    async fn handle_query(&self, query: Bytes) -> Result<Bytes> {
        let start = std::time::Instant::now();
        self.stats.inc_total();
        let raw_query = query.clone();
        
        let result = match self.handle_query_internal(query).await {
            Ok(response) => Ok(response),
            Err(e) => {
                self.stats.inc_failed();
                debug!("Query handling failed: {}", e);
                if let Ok(message) = Message::from_bytes(&raw_query) {
                    if let Ok(response) = self.build_servfail(&message) {
                        return Ok(response);
                    }
                }
                Err(e)
            }
        };
        
        // Record latency
        let elapsed_micros = start.elapsed().as_micros() as u64;
        self.stats.record_latency_micros(elapsed_micros);
        
        result
    }

    async fn handle_query_internal(&self, query: Bytes) -> Result<Bytes> {
        
        // Parse query
        let message = Message::from_bytes(&query)?;
        let id = message.id();
        
        // Get query name and type
        let query_name = message
            .queries()
            .first()
            .map(|q| q.name().to_string())
            .unwrap_or_default();
        
        let qtype = message.queries().first().map(|q| q.query_type().into()).unwrap_or(1u16);
        
        debug!("Query: {} type={} (id={})", query_name, qtype, id);

        // DGA (Domain Generation Algorithm) heuristic detection --
        // alert-only, logs and counts, never blocks or alters resolution.
        // MIMIR-DGA-DETECT-001.
        if self.config.dga.enabled {
            if let Some(dga_score) = dga::score(&query_name) {
                if dga_score.score >= self.config.dga.threshold {
                    self.stats.inc_dga_suspected();
                    // query_name/label are attacker-controlled and can contain
                    // raw control characters (trust-dns IDNA-decodes xn-- labels
                    // without escaping), so log them Debug-escaped to prevent
                    // forged log lines. MIMIR-DGA-DETECT-001.
                    //
                    // Dedup on the scored label before logging -- an attacker
                    // repeating the same high-scoring name can otherwise flood
                    // the log/disk at query rate (found in review).
                    let already_seen = self
                        .dga_alert_seen
                        .lock()
                        .put(dga_score.label.clone(), ())
                        .is_some();
                    if !already_seen {
                        warn!(
                            "DGA suspected: {:?} label={:?} score={:.2} reasons={:?}",
                            query_name, dga_score.label, dga_score.score, dga_score.reasons
                        );
                    }
                }
            }
        }

        // Check blocklist
        if self.config.blocklist.enabled && self.filter.is_blocked(&query_name) {
            self.stats.inc_blocked();
            debug!("Blocked: {}", query_name);
            return Ok(self.build_nxdomain(&message)?);
        }
        
        // Check cache with type-specific key (Chrome sends A+AAAA+HTTPS concurrently)
        let cache_key = format!("{}:{}", query_name, qtype);
        if self.config.cache.enabled {
            if let Some(cached) = self.cache.get(&cache_key) {
                self.stats.inc_cached();
                debug!("Cache hit: {} type={}", query_name, qtype);
                
                // Update ID in cached response
                let mut response = Message::from_bytes(&cached)?;
                response.set_id(id);
                return Ok(Bytes::from(response.to_bytes()?));
            }
        }
        
        // Resolve query using configured backend
        self.stats.inc_forwarded();
        let response = match &self.backend {
            ResolutionBackend::Forwarder(forwarder) => {
                forwarder.forward(&query).await?
            }
            ResolutionBackend::Recursive(resolver) => {
                // Pass original query ID to preserve in response
                resolver.resolve_with_id(&query_name, qtype, id).await?
            }
        };
        
        // Cache response if successful AND complete
        if self.config.cache.enabled {
            let resp_msg = Message::from_bytes(&response)?;
            if resp_msg.response_code() == ResponseCode::NoError {
                // Don't cache CNAME-only responses for A/AAAA queries (incomplete resolution)
                let should_cache = if qtype == 1 || qtype == 28 { // A or AAAA
                    resp_msg.answers().iter().any(|r| {
                        let rtype: u16 = r.record_type().into();
                        rtype == qtype // Must have actual A/AAAA record, not just CNAME
                    })
                } else {
                    true // Cache other types normally
                };
                
                if should_cache {
                    let ttl = resp_msg
                        .answers()
                        .first()
                        .map(|r| r.ttl())
                        .unwrap_or(300);
                    self.cache.insert(cache_key.clone(), response.clone(), ttl);
                    
                    // Sync to XDP for kernel acceleration
                    if let Some(sync) = &self.xdp_sync {
                        if let Some(rr_set) = resp_msg.answers().first() {
                            if let Some(rdata) = rr_set.data() {
                                if let Some(ip) = rdata.as_a() {
                                    sync.sync(&query_name, u32::from_be_bytes(ip.octets()), ttl);
                                }
                            }
                        }
                    }
                } else {
                    debug!("Skipping cache for incomplete CNAME-only response: {} type={}", query_name, qtype);
                }
            }
        }
        
        Ok(response)
    }
    
    fn build_servfail(&self, query: &Message) -> Result<Bytes> {
        let mut response = query.clone();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::ServFail);
        Ok(Bytes::from(response.to_bytes()?))
    }
    
    /// Build NXDOMAIN response for blocked domains
    fn build_nxdomain(&self, query: &Message) -> Result<Bytes> {
        let mut response = query.clone();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NXDomain);
        Ok(Bytes::from(response.to_bytes()?))
    }
    
    /// Run metrics HTTP server
    pub async fn run_metrics_server(&self) -> Result<()> {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper::{Request, Response, body::Incoming};
        use http_body_util::Full;
        use hyper_util::rt::TokioIo;
        
        let addr: SocketAddr = self.config.metrics.listen.parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!("Metrics server listening on {}", addr);
        
        let stats = self.stats.clone();
        
        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let stats = stats.clone();
            
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let stats = stats.clone();
                    async move {
                        let total = stats.queries_total.load(std::sync::atomic::Ordering::Relaxed);
                        let cached = stats.queries_cached.load(std::sync::atomic::Ordering::Relaxed);
                        let forwarded = stats.queries_forwarded.load(std::sync::atomic::Ordering::Relaxed);
                        let cache_hit_rate = if total > 0 { (cached as f64 / total as f64) * 100.0 } else { 0.0 };
                        
                        let body = format!(
                            "# HELP mimir_queries_total Total DNS queries\n\
                             # TYPE mimir_queries_total counter\n\
                             mimir_queries_total {}\n\
                             # HELP mimir_queries_cached Cached queries\n\
                             # TYPE mimir_queries_cached counter\n\
                             mimir_queries_cached {}\n\
                             # HELP mimir_queries_blocked Blocked queries\n\
                             # TYPE mimir_queries_blocked counter\n\
                             mimir_queries_blocked {}\n\
                             # HELP mimir_queries_forwarded Forwarded queries\n\
                             # TYPE mimir_queries_forwarded counter\n\
                             mimir_queries_forwarded {}\n\
                             # HELP mimir_queries_failed Failed queries\n\
                             # TYPE mimir_queries_failed counter\n\
                             mimir_queries_failed {}\n\
                             # HELP mimir_queries_dga_suspected Queries whose domain scored above the DGA suspicion threshold\n\
                             # TYPE mimir_queries_dga_suspected counter\n\
                             mimir_queries_dga_suspected {}\n\
                             # HELP mimir_cache_hit_rate Cache hit rate percentage\n\
                             # TYPE mimir_cache_hit_rate gauge\n\
                             mimir_cache_hit_rate {}\n\
                             # HELP mimir_query_duration_seconds DNS query duration\n\
                             # TYPE mimir_query_duration_seconds histogram\n\
                             mimir_query_duration_seconds_bucket{{le=\"0.001\"}} {}\n\
                             mimir_query_duration_seconds_bucket{{le=\"0.005\"}} {}\n\
                             mimir_query_duration_seconds_bucket{{le=\"0.01\"}} {}\n\
                             mimir_query_duration_seconds_bucket{{le=\"0.05\"}} {}\n\
                             mimir_query_duration_seconds_bucket{{le=\"0.1\"}} {}\n\
                             mimir_query_duration_seconds_bucket{{le=\"+Inf\"}} {}\n\
                             mimir_query_duration_seconds_sum {}\n\
                             mimir_query_duration_seconds_count {}\n",
                            total,
                            cached,
                            stats.queries_blocked.load(std::sync::atomic::Ordering::Relaxed),
                            forwarded,
                            stats.queries_failed.load(std::sync::atomic::Ordering::Relaxed),
                            stats.queries_dga_suspected.load(std::sync::atomic::Ordering::Relaxed),
                            cache_hit_rate,
                            // Histogram buckets (cumulative)
                            stats.latency_bucket_0_1ms.load(std::sync::atomic::Ordering::Relaxed),
                            stats.latency_bucket_0_1ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_1_5ms.load(std::sync::atomic::Ordering::Relaxed),
                            stats.latency_bucket_0_1ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_1_5ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_5_10ms.load(std::sync::atomic::Ordering::Relaxed),
                            stats.latency_bucket_0_1ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_1_5ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_5_10ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_10_50ms.load(std::sync::atomic::Ordering::Relaxed),
                            stats.latency_bucket_0_1ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_1_5ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_5_10ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_10_50ms.load(std::sync::atomic::Ordering::Relaxed) +
                            stats.latency_bucket_50_100ms.load(std::sync::atomic::Ordering::Relaxed),
                            total,  // +Inf bucket = all queries
                            // Sum in seconds (convert from microseconds)
                            stats.latency_sum_micros.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1_000_000.0,
                            total,  // count = total queries
                        );
                        Ok::<_, std::convert::Infallible>(
                            Response::new(Full::new(Bytes::from(body)))
                        )
                    }
                });
                
                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    debug!("Metrics error: {}", e);
                }
            });
        }
    }
}
