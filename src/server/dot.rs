//! DNS-over-TLS (DoT) Server Module
//!
//! RFC 7858 - DNS over Transport Layer Security
//! Port 853 - Full TLS encryption for DNS queries

use anyhow::Result;
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::server::DnsServer;

/// DNS-over-TLS Configuration
pub struct DotConfig {
    pub cert_path: String,
    pub key_path: String,
    pub listen_addr: String,
}

impl DnsServer {
    /// Run DNS-over-TLS server (RFC 7858)
    pub async fn run_dot(
        self: Arc<Self>,
        addr: SocketAddr,
        cert_path: &str,
        key_path: &str,
    ) -> Result<()> {
        // Load TLS certificates
        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;
        
        // Build TLS config
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;
        
        info!("🔐 DNS-over-TLS (DoT) server listening on {}", addr);
        
        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let server = self.clone();
            
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(mut tls_stream) => {
                        debug!("DoT connection from {}", peer);
                        
                        // Handle multiple queries on same connection (RFC 7858)
                        loop {
                            // Read 2-byte length prefix
                            let mut len_buf = [0u8; 2];
                            if tls_stream.read_exact(&mut len_buf).await.is_err() {
                                break;
                            }
                            let len = u16::from_be_bytes(len_buf) as usize;
                            
                            if len == 0 || len > 65535 {
                                break;
                            }
                            
                            // Read DNS message
                            let mut buf = vec![0u8; len];
                            if tls_stream.read_exact(&mut buf).await.is_err() {
                                break;
                            }
                            
                            // Process query
                            match server.handle_query(Bytes::from(buf)).await {
                                Ok(response) => {
                                    // Write length prefix + response
                                    let len_bytes = (response.len() as u16).to_be_bytes();
                                    if tls_stream.write_all(&len_bytes).await.is_err() {
                                        break;
                                    }
                                    if tls_stream.write_all(&response).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    debug!("DoT query error from {}: {}", peer, e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("TLS handshake failed from {}: {}", peer, e);
                    }
                }
            });
        }
    }
}

/// Load certificates from PEM file
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    Ok(certs)
}

/// Load private key from PEM file
fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    
    // Try PKCS8 first, then RSA, then EC
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", path))?;
    
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dot_port() {
        // DoT standard port is 853
        let addr: SocketAddr = "0.0.0.0:853".parse().unwrap();
        assert_eq!(addr.port(), 853);
    }
}
