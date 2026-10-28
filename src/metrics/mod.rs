//! Metrics Module
//!
//! Prometheus metrics export for RUNUT.

use prometheus::{Counter, Gauge, Histogram, HistogramOpts, Opts, Registry};
use std::sync::Arc;

/// RUNUT metrics
pub struct Metrics {
    pub registry: Registry,
    
    // Counters
    pub queries_total: Counter,
    pub queries_cached: Counter,
    pub queries_blocked: Counter,
    pub queries_forwarded: Counter,
    pub queries_failed: Counter,
    
    // Gauges
    pub cache_size: Gauge,
    pub blocklist_size: Gauge,
    pub upstreams_healthy: Gauge,
    
    // Histograms
    pub query_duration: Histogram,
}

impl Metrics {
    /// Create new metrics registry
    pub fn new() -> Self {
        let registry = Registry::new();
        
        // Counters
        let queries_total = Counter::with_opts(
            Opts::new("runut_queries_total", "Total DNS queries received")
        ).unwrap();
        
        let queries_cached = Counter::with_opts(
            Opts::new("runut_queries_cached", "Queries served from cache")
        ).unwrap();
        
        let queries_blocked = Counter::with_opts(
            Opts::new("runut_queries_blocked", "Queries blocked by filter")
        ).unwrap();
        
        let queries_forwarded = Counter::with_opts(
            Opts::new("runut_queries_forwarded", "Queries forwarded to upstream")
        ).unwrap();
        
        let queries_failed = Counter::with_opts(
            Opts::new("runut_queries_failed", "Failed queries")
        ).unwrap();
        
        // Gauges
        let cache_size = Gauge::with_opts(
            Opts::new("runut_cache_size", "Current cache size")
        ).unwrap();
        
        let blocklist_size = Gauge::with_opts(
            Opts::new("runut_blocklist_size", "Blocklist entries count")
        ).unwrap();
        
        let upstreams_healthy = Gauge::with_opts(
            Opts::new("runut_upstreams_healthy", "Number of healthy upstreams")
        ).unwrap();
        
        // Histograms
        let query_duration = Histogram::with_opts(
            HistogramOpts::new("runut_query_duration_seconds", "Query processing time")
                .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
        ).unwrap();
        
        // Register all
        registry.register(Box::new(queries_total.clone())).unwrap();
        registry.register(Box::new(queries_cached.clone())).unwrap();
        registry.register(Box::new(queries_blocked.clone())).unwrap();
        registry.register(Box::new(queries_forwarded.clone())).unwrap();
        registry.register(Box::new(queries_failed.clone())).unwrap();
        registry.register(Box::new(cache_size.clone())).unwrap();
        registry.register(Box::new(blocklist_size.clone())).unwrap();
        registry.register(Box::new(upstreams_healthy.clone())).unwrap();
        registry.register(Box::new(query_duration.clone())).unwrap();
        
        Self {
            registry,
            queries_total,
            queries_cached,
            queries_blocked,
            queries_forwarded,
            queries_failed,
            cache_size,
            blocklist_size,
            upstreams_healthy,
            query_duration,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
