//! DNS-over-QUIC (DoQ) Server Module
//!
//! RFC 9250 - DNS over Dedicated QUIC Connections
//! Uses QUIC protocol for low-latency encrypted DNS
//! Port 853 (shared with DoT, differentiated by protocol)

use anyhow::Result;
use bytes::Bytes;
use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use crate::server::DnsServer;

/// ALPN protocol identifier for DoQ
const DOQ_ALPN: &[u8] = b"doq";

impl DnsServer {
    /// Run DNS-over-QUIC server (RFC 9250)
    ///
    /// This is the fastest encrypted DNS protocol:
    /// - 0-RTT connection establishment (for resumed connections)
    /// - Multiplexed streams (no head-of-line blocking)
    /// - Built-in encryption
    pub async fn run_doq(
        self: Arc<Self>,
        addr: SocketAddr,
        cert_path: &str,
        key_path: &str,
    ) -> Result<()> {
        // Load TLS certificates
        let certs = load_certs_doq(cert_path)?;
        let key = load_key_doq(key_path)?;
        
        // Build crypto config with DoQ ALPN
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        
        crypto.alpn_protocols = vec![DOQ_ALPN.to_vec()];
        
        // Configure QUIC transport
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        
        // Build server config
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?
        ));
        server_config.transport_config(Arc::new(transport));
        
        // Create QUIC endpoint
        let endpoint = Endpoint::server(server_config, addr)?;
        
        info!("⚡ DNS-over-QUIC (DoQ) server listening on {}", addr);
        info!("   Protocol: QUIC with 0-RTT support");
        info!("   ALPN: doq");
        
        // Accept connections
        while let Some(incoming) = endpoint.accept().await {
            let server = self.clone();
            
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        let peer = connection.remote_address();
                        debug!("DoQ connection from {}", peer);
                        
                        // Handle streams
                        loop {
                            match connection.accept_bi().await {
                                Ok((mut send, mut recv)) => {
                                    let server = server.clone();
                                    
                                    tokio::spawn(async move {
                                        // RFC 9250: Read 2-byte length prefix + DNS query
                                        let mut len_buf = [0u8; 2];
                                        if recv.read_exact(&mut len_buf).await.is_err() {
                                            return;
                                        }
                                        let len = u16::from_be_bytes(len_buf) as usize;
                                        
                                        if len == 0 || len > 65535 {
                                            return;
                                        }
                                        
                                        let mut buf = vec![0u8; len];
                                        if recv.read_exact(&mut buf).await.is_err() {
                                            return;
                                        }
                                        
                                        // Process query
                                        match server.handle_query(Bytes::from(buf), Some(peer)).await {
                                            Ok(response) => {
                                                // Write response with length prefix
                                                let len_bytes = (response.len() as u16).to_be_bytes();
                                                let _ = send.write_all(&len_bytes).await;
                                                let _ = send.write_all(&response).await;
                                                let _ = send.finish();
                                            }
                                            Err(e) => {
                                                debug!("DoQ query error: {}", e);
                                            }
                                        }
                                    });
                                }
                                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                                    debug!("DoQ connection closed by peer: {}", peer);
                                    break;
                                }
                                Err(e) => {
                                    debug!("DoQ stream error from {}: {}", peer, e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("DoQ connection error: {}", e);
                    }
                }
            });
        }
        
        Ok(())
    }
}

/// Load certificates from PEM file
fn load_certs_doq(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    Ok(certs)
}

/// Load private key from PEM file
fn load_key_doq(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", path))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_doq_alpn() {
        assert_eq!(DOQ_ALPN, b"doq");
    }
    
    #[test]
    fn test_doq_port() {
        // DoQ uses same port as DoT (853)
        let addr: SocketAddr = "0.0.0.0:853".parse().unwrap();
        assert_eq!(addr.port(), 853);
    }
}
