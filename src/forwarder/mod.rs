//! DNS Forwarder Module
//!
//! Forwards DNS queries to upstream resolvers with connection pooling.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

/// DNS Forwarder with upstream rotation
pub struct DnsForwarder {
    upstreams: Vec<SocketAddr>,
    timeout: Duration,
    current: AtomicUsize,
}

impl DnsForwarder {
    /// Create new forwarder
    pub async fn new(servers: Vec<String>, timeout_ms: u64) -> Result<Self> {
        let upstreams: Result<Vec<SocketAddr>, _> = servers
            .iter()
            .map(|s| s.parse())
            .collect();
        
        let upstreams = upstreams?;
        
        if upstreams.is_empty() {
            return Err(anyhow!("No upstream servers configured"));
        }
        
        Ok(Self {
            upstreams,
            timeout: Duration::from_millis(timeout_ms),
            current: AtomicUsize::new(0),
        })
    }
    
    /// Get next upstream (round-robin)
    fn next_upstream(&self) -> SocketAddr {
        let idx = self.current.fetch_add(1, Ordering::Relaxed) % self.upstreams.len();
        self.upstreams[idx]
    }
    
    /// Forward query to upstream and return response
    pub async fn forward(&self, query: &Bytes) -> Result<Bytes> {
        // Try each upstream
        for attempt in 0..self.upstreams.len() {
            let upstream = self.next_upstream();
            
            match self.query_upstream(query, upstream).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("Upstream {} failed (attempt {}): {}", upstream, attempt + 1, e);
                }
            }
        }
        
        Err(anyhow!("All upstreams failed"))
    }
    
    /// Query single upstream
    async fn query_upstream(&self, query: &Bytes, upstream: SocketAddr) -> Result<Bytes> {
        // Create socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(upstream).await?;
        
        // Send query
        socket.send(query).await?;
        
        // Receive response with timeout
        let mut buf = vec![0u8; 4096];
        let len = timeout(self.timeout, socket.recv(&mut buf)).await??;
        
        debug!("Received {} bytes from {}", len, upstream);
        
        Ok(Bytes::copy_from_slice(&buf[..len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_forwarder_creation() {
        let forwarder = DnsForwarder::new(
            vec!["1.1.1.1:53".to_string()],
            2000
        ).await;
        
        assert!(forwarder.is_ok());
    }
    
    #[tokio::test]
    async fn test_round_robin() {
        let forwarder = DnsForwarder::new(
            vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
            2000
        ).await.unwrap();
        
        let first = forwarder.next_upstream();
        let second = forwarder.next_upstream();
        let third = forwarder.next_upstream();
        
        // Should cycle back
        assert_eq!(first, third);
        assert_ne!(first, second);
    }
}
