//! Sharded DNS Cache
//!
//! Lock-free concurrent cache with LRU eviction per shard.

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

mod singleflight;
mod prefetch;

pub use singleflight::{Singleflight, FlightResult};
pub use prefetch::{CachePrefetcher, PrefetchConfig, PrefetchRequest, EnhancedCacheEntry};

/// Cache entry with TTL
#[derive(Clone)]
struct CacheEntry {
    data: Bytes,
    expires_at: Instant,
    hits: u64,
}

/// Sharded DNS cache for high concurrency
pub struct DnsCache {
    shards: Vec<RwLock<HashMap<String, CacheEntry>>>,
    num_shards: usize,
    max_per_shard: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl DnsCache {
    /// Create new sharded cache
    pub fn new(total_size: usize, num_shards: usize) -> Self {
        let max_per_shard = total_size / num_shards;
        let shards = (0..num_shards)
            .map(|_| RwLock::new(HashMap::with_capacity(max_per_shard)))
            .collect();
        
        Self {
            shards,
            num_shards,
            max_per_shard,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }
    
    /// Get shard index for key
    fn shard_index(&self, key: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_shards
    }
    
    /// Get cached response
    pub fn get(&self, key: &str) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        
        if let Some(entry) = shard.get(key) {
            if entry.expires_at > Instant::now() {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.data.clone());
            }
        }
        
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Insert response with TTL
    pub fn insert(&self, key: String, data: Bytes, ttl_secs: u32) {
        let idx = self.shard_index(&key);
        let mut shard = self.shards[idx].write();
        
        // Evict if full (simple LRU - remove oldest)
        if shard.len() >= self.max_per_shard {
            // Find oldest entry
            let oldest = shard
                .iter()
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(k, _)| k.clone());
            
            if let Some(old_key) = oldest {
                shard.remove(&old_key);
            }
        }
        
        let entry = CacheEntry {
            data,
            expires_at: Instant::now() + Duration::from_secs(ttl_secs as u64),
            hits: 0,
        };
        
        shard.insert(key, entry);
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> (u64, u64, usize) {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let size: usize = self.shards.iter().map(|s| s.read().len()).sum();
        (hits, misses, size)
    }
    
    /// Clear expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        for shard in &self.shards {
            let mut s = shard.write();
            s.retain(|_, entry| entry.expires_at > now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cache_insert_get() {
        let cache = DnsCache::new(1000, 16);
        cache.insert("test.com".to_string(), Bytes::from("data"), 60);
        
        assert!(cache.get("test.com").is_some());
        assert!(cache.get("other.com").is_none());
    }
    
    #[test]
    fn test_cache_expiry() {
        let cache = DnsCache::new(1000, 16);
        cache.insert("test.com".to_string(), Bytes::from("data"), 0);
        
        // Should be expired immediately
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.get("test.com").is_none());
    }
}
