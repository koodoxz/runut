//! Aggressive DNS Prefetching
//!
//! Proactively refreshes cache entries before they expire

use super::{CacheEntry, DnsCache};
use bytes::Bytes;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Prefetch request
#[derive(Debug, Clone)]
pub struct PrefetchRequest {
    pub domain: String,
    pub expires_at: Instant,
    pub original_ttl: u32,
    pub hit_count: u64,
}

/// Prefetch configuration
pub struct PrefetchConfig {
    /// Prefetch when TTL drops below this percentage
    pub ttl_threshold_pct: f32,
    /// Minimum hit count to be eligible for prefetch
    pub min_hit_count: u64,
    /// Maximum concurrent prefetch operations
    pub max_concurrent: usize,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            ttl_threshold_pct: 0.30, // 30% remaining TTL
            min_hit_count: 100,
            max_concurrent: 50,
        }
    }
}

/// Aggressive cache prefetcher
pub struct CachePrefetcher {
    config: PrefetchConfig,
    prefetch_tx: mpsc::Sender<PrefetchRequest>,
}

impl CachePrefetcher {
    /// Create new prefetcher
    pub fn new(config: PrefetchConfig) -> (Self, mpsc::Receiver<PrefetchRequest>) {
        let (tx, rx) = mpsc::channel(1000);
        
        (
            Self {
                config,
                prefetch_tx: tx,
            },
            rx,
        )
    }

    /// Check if entry should be prefetched
    pub fn should_prefetch(&self, entry: &CacheEntry, original_ttl: u32) -> bool {
        let now = Instant::now();
        
        // Already expired?
        if entry.expires_at <= now {
            return false;
        }

        let ttl_remaining = entry.expires_at.duration_since(now);
        let ttl_total = Duration::from_secs(original_ttl as u64);
        
        // Calculate remaining TTL percentage
        let pct_remaining = ttl_remaining.as_secs_f32() / ttl_total.as_secs_f32();

        // Prefetch if:
        // 1. TTL < threshold (30%)
        // 2. Hit count > minimum (hot domain)
        pct_remaining < self.config.ttl_threshold_pct 
            && entry.hits >= self.config.min_hit_count
    }

    /// Queue domain for prefetch
    pub async fn queue_prefetch(&self, req: PrefetchRequest) -> bool {
        match self.prefetch_tx.try_send(req.clone()) {
            Ok(_) => {
                debug!("Queued prefetch for {}", req.domain);
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("Prefetch queue full, skipping {}", req.domain);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                false
            }
        }
    }
}

/// Enhanced cache entry with prefetch metadata
#[derive(Clone)]
pub struct EnhancedCacheEntry {
    pub data: Bytes,
    pub expires_at: Instant,
    pub hits: u64,
    pub original_ttl: u32,
    pub last_prefetch: Option<Instant>,
}

impl From<CacheEntry> for EnhancedCacheEntry {
    fn from(entry: CacheEntry) -> Self {
        Self {
            data: entry.data,
            expires_at: entry.expires_at,
            hits: entry.hits,
            original_ttl: 300, // Default
            last_prefetch: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_prefetch_ttl_threshold() {
        let config = PrefetchConfig::default();
        let prefetcher = CachePrefetcher::new(config).0;

        // TTL 100s, 20% remaining (20s) -> should prefetch
        let entry = CacheEntry {
            data: Bytes::from("test"),
            expires_at: Instant::now() + Duration::from_secs(20),
            hits: 200,
        };

        assert!(prefetcher.should_prefetch(&entry, 100));
    }

    #[test]
    fn test_should_not_prefetch_low_hits() {
        let config = PrefetchConfig::default();
        let prefetcher = CachePrefetcher::new(config).0;

        // Low hit count
        let entry = CacheEntry {
            data: Bytes::from("test"),
            expires_at: Instant::now() + Duration::from_secs(20),
            hits: 50, // Below threshold
        };

        assert!(!prefetcher.should_prefetch(&entry, 100));
    }

    #[test]
    fn test_should_not_prefetch_high_ttl() {
        let config = PrefetchConfig::default();
        let prefetcher = CachePrefetcher::new(config).0;

        // High TTL remaining (80%)
        let entry = CacheEntry {
            data: Bytes::from("test"),
            expires_at: Instant::now() + Duration::from_secs(80),
            hits: 200,
        };

        assert!(!prefetcher.should_prefetch(&entry, 100));
    }
}
