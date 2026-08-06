//! Block Filter Module
//!
//! Bloom filter based domain blocking for O(1) lookup.

use anyhow::Result;
use bloomfilter::Bloom;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, info};

/// Bloom filter based block list
pub struct BlockFilter {
    filter: RwLock<Bloom<String>>,
    count: AtomicUsize,
    bloom_size: usize,
}

impl BlockFilter {
    /// Create new block filter
    pub fn new(bloom_size: usize) -> Self {
        // false positive rate ~0.01 (1%)
        let filter = Bloom::new_for_fp_rate(bloom_size, 0.01);
        
        Self {
            filter: RwLock::new(filter),
            count: AtomicUsize::new(0),
            bloom_size,
        }
    }
    
    /// Check if domain is blocked
    pub fn is_blocked(&self, domain: &str) -> bool {
        let normalized = self.normalize_domain(domain);
        let filter = self.filter.read();
        filter.check(&normalized)
    }
    
    /// Add domain to blocklist
    pub fn add(&self, domain: &str) {
        let normalized = self.normalize_domain(domain);
        let mut filter = self.filter.write();
        filter.set(&normalized);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Normalize domain for consistent lookup
    fn normalize_domain(&self, domain: &str) -> String {
        domain
            .trim()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string()
    }
    
    /// Load blocklist from URL or file
    pub async fn load_source(&self, source: &str) -> Result<usize> {
        let content = if source.starts_with("http://") || source.starts_with("https://") {
            // HTTP fetch
            let response = reqwest::get(source).await?;
            response.text().await?
        } else {
            // Local file
            std::fs::read_to_string(source)?
        };
        
        let mut count = 0;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse hosts file format: "0.0.0.0 domain.com"
            if let Some(domain) = self.parse_hosts_line(line) {
                self.add(&domain);
                count += 1;
            }
        }
        
        info!("Loaded {} domains from {}", count, source);
        Ok(count)
    }
    
    /// Parse hosts file line format
    fn parse_hosts_line(&self, line: &str) -> Option<String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        // Format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        if parts.len() >= 2 {
            let ip = parts[0];
            if ip == "0.0.0.0" || ip == "127.0.0.1" {
                let domain = parts[1];
                // Skip localhost entries
                if domain != "localhost" 
                    && domain != "localhost.localdomain"
                    && domain != "local" 
                {
                    return Some(domain.to_string());
                }
            }
        }
        
        None
    }
    
    /// Get number of entries
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// Clear and reset filter
    pub fn clear(&self) {
        let new_filter = Bloom::new_for_fp_rate(self.bloom_size, 0.01);
        *self.filter.write() = new_filter;
        self.count.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_block_filter() {
        let filter = BlockFilter::new(10000);
        filter.add("malware.com");
        filter.add("phishing.net");
        
        assert!(filter.is_blocked("malware.com"));
        assert!(filter.is_blocked("MALWARE.COM")); // Case insensitive
        assert!(filter.is_blocked("malware.com.")); // Trailing dot
        assert!(!filter.is_blocked("safe.com"));
    }
    
    #[test]
    fn test_parse_hosts() {
        let filter = BlockFilter::new(10000);
        
        assert_eq!(
            filter.parse_hosts_line("0.0.0.0 malware.com"),
            Some("malware.com".to_string())
        );
        
        assert_eq!(
            filter.parse_hosts_line("127.0.0.1 badsite.net"),
            Some("badsite.net".to_string())
        );
        
        assert_eq!(
            filter.parse_hosts_line("# comment"),
            None
        );
        
        assert_eq!(
            filter.parse_hosts_line("0.0.0.0 localhost"),
            None
        );
    }
}
