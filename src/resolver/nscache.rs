//! NS Cache Module
//!
//! Caches nameserver records per zone for efficient recursive resolution.

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Cached NS entry with TTL
struct NSEntry {
    servers: Vec<String>,
    expires: Instant,
}

/// NS Cache for recursive resolver
pub struct NSCache {
    cache: DashMap<String, NSEntry>,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl NSCache {
    /// Create new NS cache
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(86400), // 1 day
        }
    }
    
    /// Get cached NS servers for a zone
    pub fn get(&self, zone: &str) -> Option<Vec<String>> {
        let zone_lower = zone.to_lowercase();
        if let Some(entry) = self.cache.get(&zone_lower) {
            if entry.expires > Instant::now() {
                return Some(entry.servers.clone());
            }
            // Entry expired, will be cleaned up lazily
        }
        None
    }
    
    /// Set NS servers for a zone with TTL
    pub fn set(&self, zone: &str, servers: Vec<String>, ttl: Duration) {
        // Clamp TTL to min/max
        let ttl = ttl.max(self.min_ttl).min(self.max_ttl);
        
        let entry = NSEntry {
            servers,
            expires: Instant::now() + ttl,
        };
        
        self.cache.insert(zone.to_lowercase(), entry);
    }
    
    /// Check if zone is cached
    pub fn contains(&self, zone: &str) -> bool {
        self.get(zone).is_some()
    }
    
    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }
    
    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
    
    /// Clean expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| entry.expires > now);
    }
}

impl Default for NSCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cache_set_get() {
        let cache = NSCache::new();
        cache.set("example.com", vec!["ns1.example.com".to_string()], Duration::from_secs(300));
        
        let result = cache.get("example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0], "ns1.example.com");
    }
    
    #[test]
    fn test_cache_case_insensitive() {
        let cache = NSCache::new();
        cache.set("EXAMPLE.COM", vec!["ns1.example.com".to_string()], Duration::from_secs(300));
        
        let result = cache.get("example.com");
        assert!(result.is_some());
    }
}
