//! MIMIR-RS Configuration Module
//! 
//! Handles YAML configuration parsing and validation.

use serde::{Deserialize, Serialize};
use std::path::Path;
use anyhow::Result;

/// Main configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Listen addresses
    #[serde(default)]
    pub listen: ListenConfig,
    
    /// Upstream DNS servers (used when mode = "forward")
    #[serde(default)]
    pub upstream: Option<UpstreamConfig>,
    
    /// Resolver configuration (used when mode = "recursive")
    #[serde(default)]
    pub resolver: Option<ResolverYamlConfig>,
    
    /// Resolution mode: "forward" (use upstream) or "recursive" (from root)
    #[serde(default = "default_mode")]
    pub mode: String,
    
    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,
    
    /// Blocklist configuration
    #[serde(default)]
    pub blocklist: BlocklistConfig,

    /// DGA (Domain Generation Algorithm) heuristic detection -- alert-only,
    /// no block capability. MIMIR-DGA-DETECT-001.
    #[serde(default)]
    pub dga: DgaConfig,

    /// SVALINN integration
    #[serde(default)]
    pub svalinn: SvalinnConfig,
    
    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,
    
    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
    
    /// TLS configuration (for DoT, DoH, DoQ)
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    
    /// Number of worker threads (0 = auto-detect)
    #[serde(default)]
    pub workers: usize,
}

fn default_mode() -> String { "recursive".to_string() }

/// Recursive resolver configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResolverYamlConfig {
    /// Query timeout in milliseconds
    #[serde(default = "default_resolver_timeout")]
    pub timeout_ms: u64,
    
    /// Maximum retry attempts per server
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    
    /// Maximum resolution depth (to prevent loops)
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    
    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    
    /// Enable IPv6 nameservers (default: false due to VPS limitations)
    #[serde(default = "default_ipv6_enabled")]
    pub ipv6_enabled: bool,
}

impl Default for ResolverYamlConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_resolver_timeout(),
            max_retries: default_max_retries(),
            max_depth: default_max_depth(),
            pool_size: default_pool_size(),
            ipv6_enabled: default_ipv6_enabled(),
        }
    }
}

fn default_resolver_timeout() -> u64 { 2000 }
fn default_max_retries() -> usize { 3 }
fn default_max_depth() -> usize { 30 }
fn default_pool_size() -> usize { 50 }
fn default_ipv6_enabled() -> bool { false }

/// TLS configuration for encrypted DNS protocols
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TlsConfig {
    /// Path to TLS certificate file (PEM)
    #[serde(default)]
    pub cert_path: String,
    
    /// Path to TLS private key file (PEM)
    #[serde(default)]
    pub key_path: String,
}

/// Number of worker threads (0 = auto-detect CPU cores)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Workers(pub usize);

impl Default for Workers {
    fn default() -> Self {
        Workers(0) // 0 means auto-detect
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    /// UDP listen address
    #[serde(default = "default_udp")]
    pub udp: String,
    
    /// TCP listen address
    #[serde(default = "default_tcp")]
    pub tcp: String,
    
    /// DNS-over-TLS address (optional)
    pub dot: Option<String>,
    
    /// DNS-over-HTTPS address (optional)
    pub doh: Option<String>,
    
    /// DNS-over-QUIC address (optional)
    pub doq: Option<String>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            udp: default_udp(),
            tcp: default_tcp(),
            dot: None,
            doh: None,
            doq: None,
        }
    }
}

fn default_udp() -> String { "0.0.0.0:53".to_string() }
fn default_tcp() -> String { "0.0.0.0:53".to_string() }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    /// List of upstream DNS servers
    pub servers: Vec<String>,
    
    /// Query timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    
    /// Enable TCP fallback for truncated responses
    #[serde(default = "default_true")]
    pub tcp_fallback: bool,
}

fn default_timeout() -> u64 { 2000 }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Enable caching
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Maximum cache entries
    #[serde(default = "default_cache_size")]
    pub size: usize,
    
    /// Number of cache shards (for concurrency)
    #[serde(default = "default_shards")]
    pub shards: usize,
    
    /// Minimum TTL override (seconds)
    #[serde(default)]
    pub min_ttl: Option<u32>,
    
    /// Maximum TTL override (seconds)
    #[serde(default)]
    pub max_ttl: Option<u32>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size: default_cache_size(),
            shards: default_shards(),
            min_ttl: None,
            max_ttl: None,
        }
    }
}

fn default_cache_size() -> usize { 50000 }
fn default_shards() -> usize { 64 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlocklistConfig {
    /// Enable blocklist
    #[serde(default)]
    pub enabled: bool,
    
    /// Bloom filter size (bits)
    #[serde(default = "default_bloom_size")]
    pub bloom_size: usize,
    
    /// Blocklist sources (URLs or file paths)
    #[serde(default)]
    pub sources: Vec<String>,
    
    /// Refresh interval in seconds
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bloom_size: default_bloom_size(),
            sources: Vec::new(),
            refresh_interval_secs: default_refresh(),
        }
    }
}

fn default_bloom_size() -> usize { 1_000_000 }
fn default_refresh() -> u64 { 3600 }

/// DGA heuristic detection configuration. Ships disabled by default, same
/// as BlocklistConfig above -- a new detector on a live production resolver
/// should be an explicit opt-in, not silently active. Alert-only (logs a
/// warning); has no block/deny capability in this REQ.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DgaConfig {
    /// Enable DGA detection logging
    #[serde(default)]
    pub enabled: bool,

    /// Suspicion score threshold in [0.0, 1.0] above which a query is
    /// logged as DGA-suspected. See src/dga.rs for how the score is
    /// computed.
    #[serde(default = "default_dga_threshold")]
    pub threshold: f64,
}

impl Default for DgaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_dga_threshold(),
        }
    }
}

fn default_dga_threshold() -> f64 { 0.5 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SvalinnConfig {
    /// Enable SVALINN integration
    #[serde(default)]
    pub enabled: bool,
    
    /// SVALINN API URL
    #[serde(default)]
    pub url: String,
    
    /// API key (can use ${ENV_VAR} syntax)
    #[serde(default)]
    pub api_key: String,
    
    /// Sync interval in seconds
    #[serde(default = "default_sync")]
    pub sync_interval_secs: u64,
}

impl Default for SvalinnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            api_key: String::new(),
            sync_interval_secs: default_sync(),
        }
    }
}

fn default_sync() -> u64 { 300 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    #[serde(default)]
    pub enabled: bool,
    
    /// Metrics listen address
    #[serde(default = "default_metrics")]
    pub listen: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics(),
        }
    }
}

fn default_metrics() -> String { "0.0.0.0:9153".to_string() }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_level")]
    pub level: String,
    
    /// JSON format output
    #[serde(default)]
    pub json: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            json: false,
        }
    }
}

fn default_level() -> String { "info".to_string() }

impl Config {
    /// Load configuration from YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        // dga.threshold is compared via `>=` against an f64 score -- NaN
        // makes that comparison always false (detector silently never
        // fires, no error), and a value outside [0.0, 1.0] is either
        // dead weight (>1.0, nothing can reach it) or fires on every
        // scored query (<=0.0). Found in review; fail loudly instead of
        // either silent failure mode.
        if !(0.0..=1.0).contains(&config.dga.threshold) {
            anyhow::bail!(
                "dga.threshold must be in [0.0, 1.0], got {}",
                config.dga.threshold
            );
        }
        Ok(config)
    }
    
    /// Expand environment variables in config values
    pub fn expand_env(&mut self) {
        // Expand SVALINN API key
        if self.svalinn.api_key.starts_with("${") && self.svalinn.api_key.ends_with("}") {
            let var_name = &self.svalinn.api_key[2..self.svalinn.api_key.len()-1];
            if let Ok(value) = std::env::var(var_name) {
                self.svalinn.api_key = value;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        // Test recursive mode (default)
        let yaml = r#"
mode: recursive
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.listen.udp, "0.0.0.0:53");
        assert_eq!(config.cache.size, 50000);
        assert_eq!(config.mode, "recursive");
    }
    
    #[test]
    fn test_forward_config() {
        // Test forward mode with upstream
        let yaml = r#"
mode: forward
upstream:
  servers:
    - "1.1.1.1:53"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, "forward");
        assert!(config.upstream.is_some());
        assert_eq!(config.upstream.unwrap().servers[0], "1.1.1.1:53");
    }
}
