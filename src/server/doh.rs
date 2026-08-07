//! DNS-over-HTTPS (DoH) Server Module
//!
//! RFC 8484 - DNS Queries over HTTPS
//! Uses HTTP/2 with TLS, typically on port 443
//! Supports both GET (?dns=base64) and POST (application/dns-message)

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::server::DnsServer;

/// DNS-over-HTTPS MIME type
const DNS_MESSAGE_TYPE: &str = "application/dns-message";

impl DnsServer {
    /// Run DNS-over-HTTPS server (RFC 8484)
    pub async fn run_doh(
        self: Arc<Self>,
        addr: SocketAddr,
        cert_path: &str,
        key_path: &str,
    ) -> Result<()> {
        // Load TLS certificates
        let certs = load_certs_doh(cert_path)?;
        let key = load_key_doh(key_path)?;
        
        // Build TLS config with ALPN for HTTP/2
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        
        // Enable HTTP/2 and HTTP/1.1
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;
        
        info!("🌐 DNS-over-HTTPS (DoH) server listening on {}", addr);
        info!("   Endpoints: /dns-query (GET/POST), /.well-known/dns-query");
        
        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let server = self.clone();
            
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        let server = server.clone();
                        
                        let service = service_fn(move |req| {
                            let server = server.clone();
                            async move {
                                handle_doh_request(req, server, peer).await
                            }
                        });
                        
                        // Use HTTP/1 for simplicity (can upgrade to HTTP/2)
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                        {
                            debug!("DoH HTTP error from {}: {}", peer, e);
                        }
                    }
                    Err(e) => {
                        debug!("DoH TLS handshake failed from {}: {}", peer, e);
                    }
                }
            });
        }
    }
}

/// Handle DoH HTTP request
async fn handle_doh_request(
    req: Request<Incoming>,
    server: Arc<DnsServer>,
    peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path();
    
    // Handle CORS preflight for browser compatibility (RFC 8484)
    if req.method() == Method::OPTIONS {
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type")
            .header("Access-Control-Max-Age", "86400")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    
    // Only handle /dns-query and /.well-known/dns-query
    if path != "/dns-query" && path != "/.well-known/dns-query" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Access-Control-Allow-Origin", "*")
            .body(Full::new(Bytes::from("404 Not Found")))
            .unwrap());
    }
    
    let dns_query = match *req.method() {
        Method::GET => {
            // GET /?dns=base64url encoded query
            if let Some(query) = req.uri().query() {
                extract_dns_from_query(query)
            } else {
                None
            }
        }
        Method::POST => {
            // POST with application/dns-message body
            let content_type = req.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            
            if !content_type.contains(DNS_MESSAGE_TYPE) {
                return Ok(Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Full::new(Bytes::from("415 Unsupported Media Type")))
                    .unwrap());
            }
            
            // Read body
            match req.collect().await {
                Ok(body) => Some(body.to_bytes()),
                Err(_) => None,
            }
        }
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from("405 Method Not Allowed")))
                .unwrap());
        }
    };
    
    let dns_query = match dns_query {
        Some(q) if !q.is_empty() => q,
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(Bytes::from("400 Bad Request - Invalid DNS query")))
                .unwrap());
        }
    };
    
    // Process DNS query
    match server.handle_query(dns_query, Some(peer)).await {
        Ok(response) => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", DNS_MESSAGE_TYPE)
                .header("Content-Length", response.len().to_string())
                .header("Access-Control-Allow-Origin", "*")
                .header("Cache-Control", "max-age=300")
                .body(Full::new(response))
                .unwrap())
        }
        Err(e) => {
            debug!("DoH query processing error: {}", e);
            let body = Bytes::from("500 DNS Processing Error");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Length", body.len().to_string())
                .header("Access-Control-Allow-Origin", "*")
                .body(Full::new(body))
                .unwrap())
        }
    }
}

/// Extract DNS query from URL query string (?dns=base64)
fn extract_dns_from_query(query: &str) -> Option<Bytes> {
    for param in query.split('&') {
        if let Some(value) = param.strip_prefix("dns=") {
            // Decode base64url
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(value) {
                return Some(Bytes::from(decoded));
            }
        }
    }
    None
}

/// Load certificates from PEM file
fn load_certs_doh(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    Ok(certs)
}

/// Load private key from PEM file  
fn load_key_doh(path: &str) -> Result<PrivateKeyDer<'static>> {
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
    fn test_extract_dns_query() {
        // Example base64url encoded DNS query for google.com A
        let query = "dns=AAABAAABAAAAAAAAB2dvb2dsZQNjb20AAAEAAQ";
        let result = extract_dns_from_query(query);
        assert!(result.is_some());
    }
    
    #[test]
    fn test_doh_content_type() {
        assert_eq!(DNS_MESSAGE_TYPE, "application/dns-message");
    }
}
