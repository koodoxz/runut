//! Root Hints Management
//!
//! Contains the 13 root DNS servers used for bootstrapping resolution.
//! Updated periodically from IANA: https://www.iana.org/domains/root/servers

use parking_lot::RwLock;
use rand::seq::SliceRandom;
use std::net::SocketAddr;

/// Root DNS server info
#[derive(Clone, Debug)]
pub struct RootServer {
    pub name: &'static str,
    pub ipv4: &'static str,
    pub ipv6: &'static str,
}

/// Official IANA root servers (as of 2024)
const ROOT_SERVERS: [RootServer; 13] = [
    RootServer { name: "a.root-servers.net", ipv4: "198.41.0.4", ipv6: "2001:503:ba3e::2:30" },
    RootServer { name: "b.root-servers.net", ipv4: "170.247.170.2", ipv6: "2801:1b8:10::b" },
    RootServer { name: "c.root-servers.net", ipv4: "192.33.4.12", ipv6: "2001:500:2::c" },
    RootServer { name: "d.root-servers.net", ipv4: "199.7.91.13", ipv6: "2001:500:2d::d" },
    RootServer { name: "e.root-servers.net", ipv4: "192.203.230.10", ipv6: "2001:500:a8::e" },
    RootServer { name: "f.root-servers.net", ipv4: "192.5.5.241", ipv6: "2001:500:2f::f" },
    RootServer { name: "g.root-servers.net", ipv4: "192.112.36.4", ipv6: "2001:500:12::d0d" },
    RootServer { name: "h.root-servers.net", ipv4: "198.97.190.53", ipv6: "2001:500:1::53" },
    RootServer { name: "i.root-servers.net", ipv4: "192.36.148.17", ipv6: "2001:7fe::53" },
    RootServer { name: "j.root-servers.net", ipv4: "192.58.128.30", ipv6: "2001:503:c27::2:30" },
    RootServer { name: "k.root-servers.net", ipv4: "193.0.14.129", ipv6: "2001:7fd::1" },
    RootServer { name: "l.root-servers.net", ipv4: "199.7.83.42", ipv6: "2001:500:9f::42" },
    RootServer { name: "m.root-servers.net", ipv4: "202.12.27.33", ipv6: "2001:dc3::35" },
];

/// Root hints manager
pub struct RootHints {
    servers: RwLock<Vec<SocketAddr>>,
}

impl RootHints {
    /// Create and load root hints
    pub fn new() -> Self {
        let servers: Vec<SocketAddr> = ROOT_SERVERS
            .iter()
            .filter_map(|s| format!("{}:53", s.ipv4).parse().ok())
            .collect();
        
        Self {
            servers: RwLock::new(servers),
        }
    }
    
    /// Get shuffled list of root server addresses
    pub fn get(&self) -> Vec<SocketAddr> {
        let servers = self.servers.read();
        let mut result = servers.clone();
        
        // Shuffle for load distribution
        let mut rng = rand::thread_rng();
        result.shuffle(&mut rng);
        
        result
    }
    
    /// Get number of root servers
    pub fn count(&self) -> usize {
        self.servers.read().len()
    }
}

impl Default for RootHints {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_root_hints_load() {
        let hints = RootHints::new();
        assert_eq!(hints.count(), 13);
    }
    
    #[test]
    fn test_root_hints_get() {
        let hints = RootHints::new();
        let servers = hints.get();
        assert_eq!(servers.len(), 13);
        
        // Verify all are port 53
        for server in &servers {
            assert_eq!(server.port(), 53);
        }
    }
}
