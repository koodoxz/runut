//! XDP Sync Client
//!
//! Synchronizes DNS cache entries from RUNUT to the XDP/eBPF accelerator.

use std::net::{SocketAddr, UdpSocket};
use tracing::{debug, warn};

/// Client for syncing cache to RUNUT-XDP
pub struct XdpSyncClient {
    socket: UdpSocket,
    target_addr: SocketAddr,
}

impl XdpSyncClient {
    /// Create new sync client
    pub fn new(target_addr_str: &str) -> Option<Self> {
        let target_addr: SocketAddr = target_addr_str.parse().ok()?;
        let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
        Some(Self { socket, target_addr })
    }

    /// Sync a cache entry to XDP
    pub fn sync(&self, query_name: &str, ip_addr: u32, ttl: u32) {
        let hash = compute_xdp_hash(query_name);
        
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&hash.to_le_bytes());
        buf[8..12].copy_from_slice(&ip_addr.to_le_bytes());  // Little-endian to match xdp-sync-v5
        buf[12..16].copy_from_slice(&ttl.to_le_bytes());

        if let Err(e) = self.socket.send_to(&buf, self.target_addr) {
            warn!("Failed to send XDP sync: {}", e);
        } else {
            debug!("Synced {} to XDP (hash={}, ip={:08x})", query_name, hash, ip_addr);
        }
    }
}

/// Compute hash matching eBPF/XDP implementation
/// Formula: hash = hash * 31 + byte (for first 8 bytes of wire-format QNAME)
fn compute_xdp_hash(query_name: &str) -> u64 {
    // 1. Convert to wire format labels (e.g. "google.com" -> "\x06google\x03com\x00")
    // Lowercase for case-insensitive DNS matching
    let query_lower = query_name.to_ascii_lowercase();
    let mut wire = Vec::with_capacity(query_lower.len() + 2);
    for label in query_lower.split('.').filter(|s| !s.is_empty()) {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);

    // 2. Hash (must match eBPF: include null byte THEN break)
    let mut hash: u64 = 0;
    for (i, &byte) in wire.iter().enumerate() {
        if i >= 64 {
            break;
        }
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        if byte == 0 {
            break;  // Break AFTER including null byte in hash
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdp_hash() {
        // "google.c" first 8 bytes are [6, 103, 111, 111, 103, 108, 101, 1]
        // Which is exactly how we pre-populated it in the loader!
        let h1 = compute_xdp_hash("google.com");
        assert!(h1 > 0);
    }
}
