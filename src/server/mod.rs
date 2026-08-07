//! DNS Server Module
//!
//! Handles UDP, TCP, DoT, DoH, and DoQ DNS listeners with async processing.

pub mod dot;  // DNS-over-TLS
pub mod doh;  // DNS-over-HTTPS
pub mod doq;  // DNS-over-QUIC

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::net::{IpAddr, SocketAddr};
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
use crate::svalinn::{self, DnsEvent};
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
    // Shared reqwest client for SVALINN DGA-event forwarding, built once
    // (not per-query) so TCP connections/TLS sessions to SVALINN are
    // pooled and reused. `None` when svalinn.enabled is false -- zero
    // client/connection-pool resources held in that (default) state, not
    // just zero requests sent. See `maybe_send_svalinn_dga_event`.
    svalinn_client: Option<reqwest::Client>,
    // Rate-limits how often a SVALINN POST-failure is logged, independent
    // of `dga_alert_seen`'s per-domain dedup -- see svalinn.rs's doc
    // comment on `should_log_svalinn_failure` for why both are needed.
    svalinn_failure_gate: Arc<std::sync::atomic::AtomicU64>,
    // Bounds concurrent outbound SVALINN POSTs. `dga_alert_seen` above only
    // suppresses *repeats of the same label*; a DGA-infected host querying
    // many *distinct* C2 domains (exactly the traffic this feature exists
    // to catch) would otherwise spawn one uncapped HTTP task per domain --
    // if the receiver is slow, concurrency can spike into the thousands and
    // exhaust file descriptors, which permanently kills this resolver's own
    // `listener.accept().await?` loops (found in review, HIGH-1). Acquired
    // with a non-blocking `try_acquire_owned()` in
    // `maybe_send_svalinn_dga_event` -- a full gate drops the event rather
    // than queuing or blocking.
    svalinn_inflight: Arc<tokio::sync::Semaphore>,
    // Second, narrower dedup than `dga_alert_seen`: gates whether a SVALINN
    // *send* happens, keyed on (client_ip, label) rather than label alone.
    // `dga_alert_seen` is intentionally left as label-only (it controls
    // local log-volume for the `warn!` line and must stay that way) -- but
    // reusing it to gate the SVALINN send meant only the first client IP
    // ever seen querying a given DGA domain was ever reported, making every
    // later infected host invisible to SVALINN's actor tracking (found in
    // review, MEDIUM-1). This cache exists solely to fix that.
    svalinn_send_seen: parking_lot::Mutex<lru::LruCache<(IpAddr, String), ()>>,
}

/// Maximum number of concurrent outbound SVALINN DGA-event POSTs. Chosen as
/// a small, fixed bound well below typical fd-limit headroom on this
/// latency-critical resolver -- large enough that legitimate DGA-alert
/// bursts aren't routinely dropped, small enough that even a fully-hung
/// SVALINN receiver can never come close to fd exhaustion. See
/// `svalinn_inflight`'s field doc comment (HIGH-1).
const SVALINN_MAX_INFLIGHT: usize = 32;

/// Capacity of `svalinn_send_seen`, the (client_ip, label) dedup cache that
/// gates SVALINN sends (MEDIUM-1). Same order of magnitude as
/// `dga_alert_seen`'s 10_000 -- a fixed memory bound, not time-windowed: an
/// evicted-then-reseen (client_ip, label) pair just gets re-sent, an
/// accepted imprecision favoring a hard memory bound over unbounded growth.
const SVALINN_SEND_DEDUP_CAPACITY: usize = 10_000;

/// Server statistics
pub struct ServerStats {
    pub queries_total: std::sync::atomic::AtomicU64,
    pub queries_cached: std::sync::atomic::AtomicU64,
    pub queries_blocked: std::sync::atomic::AtomicU64,
    pub queries_forwarded: std::sync::atomic::AtomicU64,
    pub queries_failed: std::sync::atomic::AtomicU64,
    pub queries_dga_suspected: std::sync::atomic::AtomicU64,
    // Count of DGA events that were NOT sent to SVALINN because the
    // concurrency gate (`svalinn_inflight`, HIGH-1) was full at the moment
    // of decision -- distinct from a send that was attempted and failed
    // (those go through `should_log_svalinn_failure` instead). Exists so
    // these silent drops are observable rather than invisible.
    pub svalinn_events_dropped: std::sync::atomic::AtomicU64,
    // Count of DGA events that were never even attempted because
    // `svalinn::build_alert_domain` returned `None` -- i.e. at least one
    // wire label in the query was not valid UTF-8 (see that function's
    // doc comment). This is a distinct, silent skip path from
    // `svalinn_events_dropped` above (gate-full) and previously had zero
    // observability: no counter, no log line, unlike the other two skip
    // paths in `maybe_send_svalinn_dga_event` (found in round-3 review,
    // NEW-1).
    pub svalinn_events_skipped_invalid_utf8: std::sync::atomic::AtomicU64,
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
            svalinn_events_dropped: std::sync::atomic::AtomicU64::new(0),
            svalinn_events_skipped_invalid_utf8: std::sync::atomic::AtomicU64::new(0),
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

    pub fn inc_svalinn_events_dropped(&self) {
        self.svalinn_events_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn inc_svalinn_events_skipped_invalid_utf8(&self) {
        self.svalinn_events_skipped_invalid_utf8.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

        // Built once here, not per-query -- reused via Clone (reqwest::Client
        // is internally Arc'd, so cloning is cheap) from the DGA alert path
        // in handle_query_internal. None when disabled: no connection pool,
        // no idle sockets held, matching dga.enabled's own zero-overhead
        // opt-in pattern. Short timeout so any single in-flight request
        // can't hang indefinitely -- this bounds per-request *duration*
        // only, NOT how many requests can be in flight at once; that's a
        // separate concern handled by `svalinn_inflight` below (found in
        // review, HIGH-1: the two are not substitutes for each other).
        let svalinn_client = if config.svalinn.enabled {
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .connect_timeout(std::time::Duration::from_secs(3))
                .build()
            {
                Ok(client) => Some(client),
                Err(e) => {
                    warn!("Failed to build SVALINN HTTP client, DGA event forwarding disabled: {}", e);
                    None
                }
            }
        } else {
            None
        };

        if config.svalinn.enabled {
            info!("SVALINN DGA event forwarding: enabled (target: {})", config.svalinn.url);
        } else {
            info!("SVALINN DGA event forwarding: disabled");
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
            svalinn_client,
            svalinn_failure_gate: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            svalinn_inflight: Arc::new(tokio::sync::Semaphore::new(SVALINN_MAX_INFLIGHT)),
            svalinn_send_seen: parking_lot::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(SVALINN_SEND_DEDUP_CAPACITY).unwrap(),
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
                                match server.handle_query(query, Some(src)).await {
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
                        match server.handle_query(query, Some(src)).await {
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
                
                match server.handle_query(Bytes::from(buf), Some(src)).await {
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
    
    /// Handle DNS query.
    ///
    /// `client_addr` is the real source address of the query, when the
    /// calling protocol path has one available (UDP/TCP/DoT/DoH/DoQ all do
    /// -- see each `run_*`/`handle_*_request` call site). It is currently
    /// used only to populate `client_ip` on outbound SVALINN DGA events;
    /// `None` here means "not sent", never a fabricated address (see
    /// `maybe_send_svalinn_dga_event`).
    async fn handle_query(&self, query: Bytes, client_addr: Option<SocketAddr>) -> Result<Bytes> {
        let start = std::time::Instant::now();
        self.stats.inc_total();
        let raw_query = query.clone();

        let result = match self.handle_query_internal(query, client_addr).await {
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

    async fn handle_query_internal(&self, query: Bytes, client_addr: Option<SocketAddr>) -> Result<Bytes> {

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
        //
        // Scored from raw wire-format label bytes (Name::iter()), NOT
        // query_name's display string -- trust-dns IDNA-decodes/unescapes
        // labels when formatting that string, which can desync a
        // dot-delimited parse and let an attacker manufacture an arbitrary
        // score. See dga.rs's doc comment on `score` for the full
        // rationale. MIMIR-DGA-DETECT-001.
        if self.config.dga.enabled {
            let query_labels: Vec<&[u8]> = message
                .queries()
                .first()
                .map(|q| q.name().iter().collect())
                .unwrap_or_default();
            if let Some(dga_score) = dga::score(&query_labels) {
                if dga_score.score >= self.config.dga.threshold {
                    self.stats.inc_dga_suspected();
                    // query_name/label are attacker-controlled and can contain
                    // raw control characters (trust-dns IDNA-decodes xn-- labels
                    // without escaping), so log them Debug-escaped to prevent
                    // forged log lines. MIMIR-DGA-DETECT-001.
                    //
                    // Dedup on the scored label before logging -- an attacker
                    // repeating the same high-scoring name can otherwise flood
                    // the log/disk at query rate (found in review). This
                    // gate controls ONLY the local `warn!` line's volume
                    // (label-only, no client_ip). It must NOT also gate
                    // whether SVALINN gets notified below -- nesting the
                    // send call inside this `if` was a real bug (round-3
                    // fix): it meant a second, third, ... Nth distinct
                    // client IP querying a label some earlier client already
                    // triggered this `warn!` for would never even reach
                    // `maybe_send_svalinn_dga_event`, making that method's
                    // own (client_ip, label) dedup (`svalinn_send_seen`)
                    // unreachable in production for every client after the
                    // first.
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

                    // Forward to SVALINN unconditionally -- i.e. regardless
                    // of `already_seen` above -- gated ONLY by
                    // `maybe_send_svalinn_dga_event`'s own internal
                    // (client_ip, label) dedup (`svalinn_send_seen`, see its
                    // field doc comment, MEDIUM-1). This call must NOT live
                    // inside the `if !already_seen` block above; see the
                    // comment on `already_seen` for the bug that shape
                    // caused (round-3 fix). The local `warn!` above and this
                    // send are now genuinely independent: this runs whether
                    // or not that log fired. Spawned, never awaited inline,
                    // so a slow/unreachable SVALINN instance can never delay
                    // DNS resolution.
                    //
                    // Gate on `svalinn_client.is_some()` BEFORE ever calling
                    // `build_alert_domain` below (round-4 fix, NEW-3):
                    // `build_alert_domain` allocates a `Vec` + per-label
                    // `String`s and does a join, so calling it unconditionally
                    // meant that allocation ran on every above-threshold DGA
                    // query even when SVALINN is disabled (the default) --
                    // directly contradicting `maybe_send_svalinn_dga_event`'s
                    // own doc comment, which promises "zero overhead in the
                    // default-disabled state". This check is just an `Option`
                    // read on `self`, so it is genuinely free. The function's
                    // own internal `svalinn_client.is_none()` check remains in
                    // place as defense-in-depth for any future call site that
                    // doesn't gate here first.
                    if self.svalinn_client.is_some() {
                        // Domain string built from the same raw wire-format
                        // label bytes the DGA scorer used (query_labels), NOT
                        // query_name's Display string -- see dga.rs's module doc
                        // comment for why (trust-dns IDNA-decodes/unescapes
                        // labels in the display form, which silently breaks
                        // correlation against other IOC feeds using the
                        // canonical ASCII/punycode form). Built via
                        // `svalinn::build_alert_domain`, NOT
                        // `String::from_utf8_lossy` per label -- lossy decoding
                        // here reintroduced the exact score-manufacturing class
                        // dga.rs's own doc comment rejects, and a naive
                        // '.'-join could desync on a literal '.' byte legally
                        // inside one wire label the same way dga.rs has a
                        // dedicated regression test against (round-3 fix; see
                        // `build_alert_domain`'s doc comment for both). `None`
                        // (non-UTF-8 label content anywhere in the domain) means
                        // skip sending this event rather than send a corrupted
                        // string.
                        match svalinn::build_alert_domain(&query_labels) {
                            Some(escaped_domain) => {
                                self.maybe_send_svalinn_dga_event(client_addr, &escaped_domain, &dga_score);
                            }
                            None => {
                                // Round-4 fix (NEW-1): this skip path
                                // previously had zero observability -- no
                                // counter, no log line -- unlike the other
                                // two skip paths inside
                                // `maybe_send_svalinn_dga_event` (disabled
                                // client, gate-full), both of which already
                                // had one. `debug!`, not `warn!`/`info!`:
                                // this is attacker-triggerable at query rate
                                // (any query with a non-UTF-8 label that
                                // also scores above the DGA threshold), so
                                // keep it low-severity/low-volume by design,
                                // matching this codebase's established
                                // caution about log-flood vectors elsewhere
                                // in this same file.
                                self.stats.inc_svalinn_events_skipped_invalid_utf8();
                                debug!(
                                    "Skipping SVALINN DGA event: query contains \
                                     a non-UTF-8 wire label, cannot build a safe \
                                     domain string (label={:?})",
                                    dga_score.label
                                );
                            }
                        }
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

    /// Fire-and-forget forward of a DGA alert to SVALINN as a `DnsEvent`
    /// POST to `{svalinn.url}/api/v1/dns-events` (see svalinn.rs's doc
    /// comment for the exact receiver contract this targets:
    /// github.com/aegis/svalinn, internal/server/handlers.go:2019).
    ///
    /// Non-blocking by construction: this method itself never `.await`s --
    /// it only decides whether to spawn, then spawns. DNS resolution is
    /// never delayed by this call regardless of SVALINN's latency or
    /// reachability.
    ///
    /// No-op (not even a spawned task) when `svalinn_client` is `None`
    /// (i.e. `svalinn.enabled` was false at startup) -- zero overhead in
    /// the default-disabled state, matching `dga.enabled`'s own pattern.
    /// This function's own check is the last line of defense for that
    /// guarantee, not the only one: as of round-4, `handle_query_internal`
    /// (this method's sole call site) also checks `svalinn_client.is_some()`
    /// itself BEFORE ever calling `svalinn::build_alert_domain` to build the
    /// `domain` argument passed in here -- that function allocates, so
    /// gating it at the call site (not just here) is what makes "zero
    /// overhead when disabled" actually true rather than just documented.
    ///
    /// The `let Some(client) = self.svalinn_client.clone() else { return }`
    /// check immediately below is not dead code left over from that
    /// reordering; keep it -- it is what protects any future call site that
    /// forgets to gate before calling `svalinn::build_alert_domain` itself.
    ///
    /// `client_ip` is REQUIRED by the receiver (400 if empty). If
    /// `client_addr` is `None` -- meaning this call site's protocol path
    /// genuinely has no real client address available -- this method skips
    /// sending rather than fabricating a placeholder IP (e.g. "0.0.0.0"),
    /// which would corrupt SVALINN's actor-tracking data on the receiving
    /// end. As of this change, every protocol path (UDP, TCP, DoT, DoH,
    /// DoQ) threads a real client address through, so this branch should
    /// not currently trigger in practice; it remains as a safety net for
    /// any future call site that doesn't.
    ///
    /// Two additional gates run before anything is spawned (both silent
    /// no-ops on their "skip" path, neither ever blocks): the
    /// `svalinn_inflight` concurrency gate FIRST (see its field doc comment
    /// and `SVALINN_MAX_INFLIGHT`, HIGH-1), then the `svalinn_send_seen`
    /// (client_ip, label) dedup (see its field doc comment, MEDIUM-1). This
    /// order is deliberate (round-3 fix): the dedup LRU is only marked
    /// "sent" once a permit is actually held, so a gate-full drop never
    /// poisons the dedup LRU with a send that didn't happen -- see the
    /// comment inside the function body for the concrete bug this fixes.
    /// Only an event that clears both actually spawns a task and consumes
    /// a permit for that task's lifetime.
    fn maybe_send_svalinn_dga_event(
        &self,
        client_addr: Option<SocketAddr>,
        domain: &str,
        dga_score: &dga::DgaScore,
    ) {
        let Some(client) = self.svalinn_client.clone() else {
            return;
        };
        let Some(addr) = client_addr else {
            debug!(
                "Skipping SVALINN DGA event: no real client address available \
                 at this protocol path (would otherwise require sending a \
                 fabricated client_ip, which SVALINN requires and uses for \
                 actor tracking)"
            );
            return;
        };

        // Non-blocking concurrency gate, checked FIRST -- before the
        // (client_ip, label) dedup LRU below. Ordering matters (round-3
        // fix): marking the dedup LRU as "sent" BEFORE checking this gate
        // was a real bug -- if the gate was full, the event was dropped
        // AND permanently marked as already-sent in the LRU, so it would
        // never be retried even after capacity freed up, silently losing
        // events during exactly the burst conditions this gate exists to
        // survive. Checking the gate first, and only marking the dedup LRU
        // once a permit is actually held (below), means a gate-full drop
        // leaves no trace in the dedup LRU, so a future retry for the same
        // (client_ip, label) pair remains possible.
        //
        // A DGA-infected host querying many *distinct* C2 domains would
        // otherwise spawn one uncapped HTTP task per domain, and a
        // slow/hung SVALINN receiver could let that spike into the
        // thousands, risking fd exhaustion (which permanently kills this
        // resolver's own accept loops). If the gate is full, drop the
        // event without even spawning a task -- don't pay for it (found in
        // review, HIGH-1).
        let Ok(permit) = self.svalinn_inflight.clone().try_acquire_owned() else {
            self.stats.inc_svalinn_events_dropped();
            debug!(
                "Dropping SVALINN DGA event: {} concurrent forwards already \
                 in flight (gate full)",
                SVALINN_MAX_INFLIGHT
            );
            return;
        };

        // Send-decision dedup keyed on (client_ip, label) -- independent of
        // `dga_alert_seen`'s label-only dedup, which gates only the local
        // `warn!` line in `handle_query_internal` and is never consulted
        // here; this method is reached regardless of whether that local
        // log fired for this label (round-3 fix -- see the call site's
        // comment). Without this dedup, only the first client IP ever seen
        // querying a given DGA domain would ever get reported to SVALINN;
        // every later infected host querying the same domain would be
        // invisible to SVALINN's actor tracking (found in review,
        // MEDIUM-1).
        //
        // `put` doubles as an atomic check-and-set under a single lock
        // hold, and only runs now that a permit is held (see the gate
        // comment above) -- an already-sent pair returns here and drops
        // the just-acquired `permit`, releasing it back to the semaphore
        // immediately rather than ever spawning.
        // ponytail: round-3's dedup-ordering fix (see the block comment
        // above) moved this `.lock()` to run on every query that reaches
        // this point when SVALINN is enabled, not just once per distinct
        // label as before -- i.e. this is now on the per-query hot path,
        // not the per-distinct-label path. NEW-2 (round-3 review): this
        // mutex's contention under sustained high-QPS DGA traffic has not
        // been benchmarked. Accepted as-is for this round (explicit user
        // decision, not a fix); benchmark before enabling `svalinn` in a
        // high-QPS production deployment.
        let send_key = (addr.ip(), dga_score.label.clone());
        let already_sent_for_client = self
            .svalinn_send_seen
            .lock()
            .put(send_key, ())
            .is_some();
        if already_sent_for_client {
            return;
        }

        let url = svalinn::build_dns_events_url(&self.config.svalinn.url);
        // api_key may be empty (unset) -- still sent as a header either way
        // for forward-compatibility. The receiver does not validate it
        // today (IP-allowlist only), so an empty/placeholder value here is
        // not a security gap introduced by this change.
        let api_key = self.config.svalinn.api_key.clone();
        let failure_gate = self.svalinn_failure_gate.clone();

        let event = DnsEvent {
            event_type: "dga".to_string(),
            client_ip: addr.ip().to_string(),
            domain: domain.to_string(),
            score: dga_score.score,
            reason: dga_score.reasons.join(","),
            actor_id: None,
            timestamp: None,
            source: Some("mimir".to_string()),
        };

        tokio::spawn(async move {
            // `permit` is moved in here and dropped (releasing the gate)
            // when this task ends, on every path -- success, rejection, or
            // send failure alike.
            let _permit = permit;
            // ponytail: Authorization: Bearer is forward-compatible only --
            // the live receiver checks IP-allowlist before this handler
            // even runs and does not validate this header today. Not a
            // real security boundary yet; do not rely on it as one.
            let result = client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&event)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    debug!("SVALINN DGA event delivered: status={}", resp.status());
                }
                Ok(resp) => {
                    if svalinn::should_log_svalinn_failure(&failure_gate) {
                        warn!(
                            "SVALINN DGA event rejected: status={} (further \
                             failures suppressed briefly to avoid log flood \
                             during an extended SVALINN outage)",
                            resp.status()
                        );
                    }
                }
                Err(e) => {
                    if svalinn::should_log_svalinn_failure(&failure_gate) {
                        warn!(
                            "SVALINN DGA event send failed: {} (further \
                             failures suppressed briefly to avoid log flood \
                             during an extended SVALINN outage)",
                            e
                        );
                    }
                }
            }
        });
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
                             # HELP mimir_svalinn_events_dropped DGA events dropped without sending because the SVALINN concurrency gate was full\n\
                             # TYPE mimir_svalinn_events_dropped counter\n\
                             mimir_svalinn_events_dropped {}\n\
                             # HELP mimir_svalinn_events_skipped_invalid_utf8 DGA events never attempted because a wire label was not valid UTF-8\n\
                             # TYPE mimir_svalinn_events_skipped_invalid_utf8 counter\n\
                             mimir_svalinn_events_skipped_invalid_utf8 {}\n\
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
                            stats.svalinn_events_dropped.load(std::sync::atomic::Ordering::Relaxed),
                            stats.svalinn_events_skipped_invalid_utf8.load(std::sync::atomic::Ordering::Relaxed),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `svalinn.enabled: false` (the default -- omitted entirely here) must
    /// mean `DnsServer::new()` genuinely does not build a `reqwest::Client`
    /// at all, not just "builds one but never uses it". Previously this was
    /// only asserted in doc comments, never tested (found in review,
    /// MEDIUM-2).
    fn disabled_config() -> Config {
        serde_yaml::from_str("mode: recursive\n").unwrap()
    }

    /// `svalinn.enabled: true` with a syntactically valid (but unreachable)
    /// target -- these tests never await the spawned HTTP send, so the
    /// target does not need to be reachable.
    fn enabled_config() -> Config {
        serde_yaml::from_str(
            "mode: recursive\nsvalinn:\n  enabled: true\n  url: \"http://127.0.0.1:9\"\n",
        )
        .unwrap()
    }

    fn sample_dga_score(label: &str) -> dga::DgaScore {
        dga::DgaScore {
            score: 0.9,
            label: label.to_string(),
            reasons: vec!["high_entropy"],
        }
    }

    #[tokio::test]
    async fn svalinn_client_is_none_when_disabled() {
        let server = DnsServer::new(disabled_config()).await.unwrap();
        assert!(
            server.svalinn_client.is_none(),
            "svalinn_client must not be built when svalinn.enabled is false"
        );
    }

    #[tokio::test]
    async fn svalinn_client_is_some_when_enabled() {
        let server = DnsServer::new(enabled_config()).await.unwrap();
        assert!(
            server.svalinn_client.is_some(),
            "svalinn_client must be built when svalinn.enabled is true"
        );
    }

    /// HIGH-1: with the concurrency gate fully exhausted, the event must be
    /// dropped (no permit consumed, no spawn) and counted via
    /// `svalinn_events_dropped`, rather than spawning an unbounded task.
    #[tokio::test]
    async fn svalinn_inflight_gate_drops_event_and_counts_it_when_full() {
        let server = DnsServer::new(enabled_config()).await.unwrap();

        // Pre-acquire every permit so the gate is exhausted before the
        // function under test ever runs.
        let mut held_permits = Vec::new();
        for _ in 0..SVALINN_MAX_INFLIGHT {
            held_permits.push(
                server
                    .svalinn_inflight
                    .clone()
                    .try_acquire_owned()
                    .expect("gate should not be exhausted yet"),
            );
        }
        assert_eq!(server.svalinn_inflight.available_permits(), 0);

        let addr: SocketAddr = "203.0.113.7:12345".parse().unwrap();
        let before = server
            .stats
            .svalinn_events_dropped
            .load(std::sync::atomic::Ordering::Relaxed);

        server.maybe_send_svalinn_dga_event(Some(addr), "evil.example.com", &sample_dga_score("evil"));

        let after = server
            .stats
            .svalinn_events_dropped
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(after, before + 1, "gate-full event must be counted as dropped");
        assert_eq!(
            server.svalinn_inflight.available_permits(),
            0,
            "a dropped event must not consume a permit"
        );

        // Keep the held permits alive for the whole assertion window above.
        drop(held_permits);
    }

    /// MEDIUM-1: the (client_ip, label) send-dedup must allow two distinct
    /// client IPs querying the same DGA label to both be sent, while a
    /// repeat from the same client IP is suppressed. Observed indirectly via
    /// the concurrency-gate permit count, since a "sent" event synchronously
    /// consumes a permit at the point `maybe_send_svalinn_dga_event` returns
    /// (before the spawned task is ever polled), and a suppressed one does
    /// not.
    #[tokio::test]
    async fn svalinn_send_dedup_keys_on_client_ip_and_label() {
        let server = DnsServer::new(enabled_config()).await.unwrap();
        assert_eq!(server.svalinn_inflight.available_permits(), SVALINN_MAX_INFLIGHT);

        let addr_a: SocketAddr = "203.0.113.7:1".parse().unwrap();
        let addr_b: SocketAddr = "203.0.113.8:1".parse().unwrap();
        let score = sample_dga_score("evil");

        // First send from client A consumes a permit.
        server.maybe_send_svalinn_dga_event(Some(addr_a), "evil.example.com", &score);
        assert_eq!(server.svalinn_inflight.available_permits(), SVALINN_MAX_INFLIGHT - 1);

        // A repeat from the SAME client A + same label must be suppressed
        // by the (client_ip, label) dedup -- no additional permit consumed.
        server.maybe_send_svalinn_dga_event(Some(addr_a), "evil.example.com", &score);
        assert_eq!(server.svalinn_inflight.available_permits(), SVALINN_MAX_INFLIGHT - 1);

        // A DIFFERENT client B querying the same label must still be sent.
        server.maybe_send_svalinn_dga_event(Some(addr_b), "evil.example.com", &score);
        assert_eq!(server.svalinn_inflight.available_permits(), SVALINN_MAX_INFLIGHT - 2);
    }

    /// `client_addr == None` must skip sending entirely -- no client, no
    /// spawn, no permit consumed (this call site never fabricates a
    /// placeholder IP).
    #[tokio::test]
    async fn svalinn_send_skipped_when_no_client_addr() {
        let server = DnsServer::new(enabled_config()).await.unwrap();
        assert_eq!(server.svalinn_inflight.available_permits(), SVALINN_MAX_INFLIGHT);

        server.maybe_send_svalinn_dga_event(None, "evil.example.com", &sample_dga_score("evil"));

        assert_eq!(
            server.svalinn_inflight.available_permits(),
            SVALINN_MAX_INFLIGHT,
            "no client address means no permit should be consumed"
        );
    }

    /// `svalinn_client == None` (disabled) must be a true no-op: no permit
    /// consumed, regardless of client_addr/dedup state.
    #[tokio::test]
    async fn svalinn_send_skipped_when_disabled() {
        let server = DnsServer::new(disabled_config()).await.unwrap();
        let addr: SocketAddr = "203.0.113.7:1".parse().unwrap();

        // Disabled state builds a permit count of SVALINN_MAX_INFLIGHT too
        // (the semaphore is always constructed), but no send should ever
        // touch it since the function returns before reaching the gate.
        server.maybe_send_svalinn_dga_event(Some(addr), "evil.example.com", &sample_dga_score("evil"));

        assert_eq!(server.svalinn_inflight.available_permits(), SVALINN_MAX_INFLIGHT);
    }

    /// `svalinn.enabled: true` + DGA detection enabled, with resolution
    /// backed by an UNREACHABLE upstream and a very short timeout, so a
    /// full `handle_query_internal` call (resolution included) completes
    /// quickly and deterministically without depending on real network
    /// reachability. `192.0.2.1` is RFC 5737 TEST-NET-1 (reserved,
    /// guaranteed non-routable), and `timeout_ms: 50` bounds the forwarder's
    /// wait for a reply that will never arrive.
    fn fast_forward_config_with_dga() -> Config {
        serde_yaml::from_str(
            "mode: forward\n\
             upstream:\n\
             \x20 servers:\n\
             \x20   - \"192.0.2.1:53\"\n\
             \x20 timeout_ms: 50\n\
             dga:\n\
             \x20 enabled: true\n\
             svalinn:\n\
             \x20 enabled: true\n\
             \x20 url: \"http://127.0.0.1:9\"\n",
        )
        .unwrap()
    }

    /// Minimal hand-rolled raw-bytes DNS query for tests that must drive
    /// `handle_query_internal` directly (mirrors `resolver::build_dns_query`'s
    /// wire-format approach, without the EDNS0 OPT record -- not needed
    /// here since this query is never actually sent anywhere reachable).
    fn build_raw_dns_query(qname: &str) -> Bytes {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // transaction id
        buf.extend_from_slice(&[0x01, 0x00]); // standard query, RD=1
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QDCOUNT=1
        for label in qname.trim_end_matches('.').split('.').filter(|s| !s.is_empty()) {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // root label
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        Bytes::from(buf)
    }

    /// Same wire-format construction as `build_raw_dns_query` above, but
    /// takes raw label byte slices directly instead of a `&str` split on
    /// `.` -- needed for the NEW-1 regression test below, which requires a
    /// label containing bytes that are not valid UTF-8 (impossible to
    /// express as a Rust `&str` literal).
    fn build_raw_dns_query_from_labels(labels: &[&[u8]]) -> Bytes {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // transaction id
        buf.extend_from_slice(&[0x01, 0x00]); // standard query, RD=1
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QDCOUNT=1
        for label in labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label);
        }
        buf.push(0x00); // root label
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        Bytes::from(buf)
    }

    /// Round-3 regression test for the headline bug: drives the REAL
    /// production call site (`handle_query_internal`), not
    /// `maybe_send_svalinn_dga_event` in isolation like round 2's
    /// `svalinn_send_dedup_keys_on_client_ip_and_label` test above did.
    /// That's exactly why round 2's test passed while the real bug was
    /// live -- it bypassed the call site where the bug actually was.
    ///
    /// The bug: `maybe_send_svalinn_dga_event` was called *inside*
    /// `if !already_seen` (the label-only local-log dedup), so a second,
    /// distinct client IP querying a label some earlier client already
    /// triggered the local `warn!` for never even reached
    /// `maybe_send_svalinn_dga_event` -- making that method's own
    /// (client_ip, label) dedup permanently unreachable in production.
    ///
    /// Uses the same "pre-exhaust the gate, observe `svalinn_events_dropped`"
    /// technique as `svalinn_inflight_gate_drops_event_and_counts_it_when_full`
    /// above: with every permit already held, any call that reaches
    /// `maybe_send_svalinn_dga_event`'s `try_acquire_owned()` gate
    /// deterministically and synchronously increments the dropped counter
    /// -- no network dependency, no timing flakiness, and critically: if a
    /// call does NOT reach that gate at all (the bug), the counter simply
    /// does not move.
    #[tokio::test]
    async fn handle_query_internal_forwards_second_distinct_client_for_already_locally_logged_label() {
        let server = DnsServer::new(fast_forward_config_with_dga()).await.unwrap();

        // Pre-exhaust the concurrency gate so any call reaching
        // `maybe_send_svalinn_dga_event`'s gate check is observable via
        // `svalinn_events_dropped` without needing the spawned HTTP send
        // to actually complete (it never even spawns when the gate is
        // full).
        let mut held_permits = Vec::new();
        for _ in 0..SVALINN_MAX_INFLIGHT {
            held_permits.push(
                server
                    .svalinn_inflight
                    .clone()
                    .try_acquire_owned()
                    .expect("gate should not be exhausted yet"),
            );
        }

        // A DGA-scoring domain (one of dga.rs's own high-scoring fixtures,
        // see `dga_like_domains_score_high`).
        let query_bytes = build_raw_dns_query("xkjqwzpqmnbvcxzl.com");

        let addr_a: SocketAddr = "203.0.113.50:1".parse().unwrap();
        let addr_b: SocketAddr = "203.0.113.51:1".parse().unwrap();

        let before = server
            .stats
            .svalinn_events_dropped
            .load(std::sync::atomic::Ordering::Relaxed);

        // Client A's query: this is the FIRST time this label is seen, so
        // the local `warn!` fires, AND the call must reach the SVALINN
        // send gate. Resolution itself fails (unreachable upstream,
        // TEST-NET-1) -- irrelevant to what this test proves, so the
        // `Result` is discarded.
        let _ = server
            .handle_query_internal(query_bytes.clone(), Some(addr_a))
            .await;

        let after_a = server
            .stats
            .svalinn_events_dropped
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            after_a,
            before + 1,
            "client A's first query for this label must reach the SVALINN \
             send gate (dropped-counter must move)"
        );

        // Client B: a DIFFERENT client IP querying the SAME label. The
        // local `warn!` dedup (`dga_alert_seen`, label-only) suppresses
        // the log for this label a second time -- but that must NOT stop
        // this call from reaching `maybe_send_svalinn_dga_event`. This is
        // the exact bug under test: before the round-3 hoisting fix, the
        // send call was nested inside `if !already_seen`, so this request
        // would never have reached the gate at all and the counter would
        // not move here.
        let _ = server
            .handle_query_internal(query_bytes.clone(), Some(addr_b))
            .await;

        let after_b = server
            .stats
            .svalinn_events_dropped
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            after_b,
            after_a + 1,
            "client B (a distinct client IP querying the same already-\
             locally-logged label) must STILL reach the SVALINN send gate \
             -- if this fails, the round-3 hoisting fix regressed and the \
             call is once again unreachable for any client after the first"
        );

        drop(held_permits);
    }

    /// Round-4 fix regression test (NEW-1): a query whose registrable label
    /// scores above the DGA threshold, but which also contains a DIFFERENT
    /// (non-registrable, leading) label that is not valid UTF-8, must skip
    /// the SVALINN send via `build_alert_domain` returning `None` -- and
    /// that skip must now be observable: `svalinn_events_skipped_invalid_utf8`
    /// increments by exactly one, and critically `maybe_send_svalinn_dga_event`
    /// must never even be reached (no permit consumed, `svalinn_events_dropped`
    /// unchanged) -- proving the `None` branch short-circuits before the send
    /// path, not just that some counter somewhere moved.
    #[tokio::test]
    async fn handle_query_internal_counts_and_logs_invalid_utf8_domain_skip() {
        let server = DnsServer::new(fast_forward_config_with_dga()).await.unwrap();

        // Leading (non-registrable) label is deliberately invalid UTF-8;
        // the registrable label ("xkjqwzpqmnbvcxzl") is the same
        // known-high-scoring fixture used elsewhere in this file, and is
        // itself valid UTF-8/ASCII so the DGA scorer still fires.
        let invalid_label: &[u8] = &[0xFF, 0xFE];
        let query_bytes = build_raw_dns_query_from_labels(&[
            invalid_label,
            b"xkjqwzpqmnbvcxzl",
            b"com",
        ]);

        let addr: SocketAddr = "203.0.113.90:1".parse().unwrap();

        let skipped_before = server
            .stats
            .svalinn_events_skipped_invalid_utf8
            .load(std::sync::atomic::Ordering::Relaxed);
        let dropped_before = server
            .stats
            .svalinn_events_dropped
            .load(std::sync::atomic::Ordering::Relaxed);
        let permits_before = server.svalinn_inflight.available_permits();

        let _ = server.handle_query_internal(query_bytes, Some(addr)).await;

        let skipped_after = server
            .stats
            .svalinn_events_skipped_invalid_utf8
            .load(std::sync::atomic::Ordering::Relaxed);
        let dropped_after = server
            .stats
            .svalinn_events_dropped
            .load(std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            skipped_after,
            skipped_before + 1,
            "a non-UTF-8 label must increment svalinn_events_skipped_invalid_utf8"
        );
        assert_eq!(
            dropped_after, dropped_before,
            "the invalid-UTF-8 skip path must never reach \
             maybe_send_svalinn_dga_event, so svalinn_events_dropped must \
             not move"
        );
        assert_eq!(
            server.svalinn_inflight.available_permits(),
            permits_before,
            "the invalid-UTF-8 skip path must never consume a concurrency permit"
        );
    }

    /// Round-4 fix regression test (NEW-3): when SVALINN is disabled, a
    /// DGA-scoring query must not even attempt `build_alert_domain` --
    /// verified here via the disabled-config path reaching the exact same
    /// point in `handle_query_internal` without panicking or behaving
    /// differently, combined with the code-inspection evidence in this
    /// round's report (the `if self.svalinn_client.is_some()` guard now
    /// wraps the `build_alert_domain` call entirely, so the allocation
    /// inside it is provably unreachable when disabled -- see call site
    /// comment). This test's role is to confirm the disabled path still
    /// behaves as a true no-op end-to-end through the real call site, not
    /// just in the isolated `maybe_send_svalinn_dga_event` unit tests above.
    #[tokio::test]
    async fn handle_query_internal_disabled_svalinn_never_reaches_send_path() {
        let mut config: Config = serde_yaml::from_str(
            "mode: forward\n\
             upstream:\n\
             \x20 servers:\n\
             \x20   - \"192.0.2.1:53\"\n\
             \x20 timeout_ms: 50\n\
             dga:\n\
             \x20 enabled: true\n",
        )
        .unwrap();
        // svalinn.enabled defaults to false -- explicit for clarity.
        config.svalinn.enabled = false;
        let server = DnsServer::new(config).await.unwrap();
        assert!(server.svalinn_client.is_none());

        // Deliberately a non-UTF-8 leading label (not a plain ASCII domain):
        // if the NEW-3 disabled-path guard were ever removed/reordered so
        // that `build_alert_domain` runs before the `svalinn_client.is_some()`
        // check, an all-ASCII query would still score >=0.5 and skip the
        // counter for an unrelated reason (DGA score too low), making the
        // assertions below pass regardless of whether the guard exists --
        // exactly the vacuous-test gap an adversarial review caught in the
        // prior version of this test. A non-UTF-8 label forces
        // build_alert_domain to return None (and, if reached, increment the
        // skip counter), so this test only stays green if the guard
        // genuinely prevents build_alert_domain from running at all.
        let query_bytes = build_raw_dns_query_from_labels(&[
            &[0xFF, 0xFE],
            b"xkjqwzpqmnbvcxzl",
            b"com",
        ]);
        let addr: SocketAddr = "203.0.113.91:1".parse().unwrap();

        let skipped_before = server
            .stats
            .svalinn_events_skipped_invalid_utf8
            .load(std::sync::atomic::Ordering::Relaxed);

        let _ = server.handle_query_internal(query_bytes, Some(addr)).await;

        let skipped_after = server
            .stats
            .svalinn_events_skipped_invalid_utf8
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            skipped_after, skipped_before,
            "disabled SVALINN must never touch the invalid-UTF-8 skip \
             counter either -- build_alert_domain must not even be called"
        );
        assert_eq!(
            server.svalinn_inflight.available_permits(),
            SVALINN_MAX_INFLIGHT,
            "disabled SVALINN must never consume a permit"
        );
    }
}
