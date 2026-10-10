//! TLS termination configuration and certificate loading utilities.

pub mod resolver;

use std::sync::Arc;
use rustls::pki_types::CertificateDer;
use rustls::server::ServerConfig;
use rustls::sign::CertifiedKey;
use thiserror::Error;

pub use resolver::DynamicCertResolver;

/// Errors loading or building TLS server configuration.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("failed to parse certificate PEM")]
    InvalidCertificate,

    #[error("failed to parse private key PEM")]
    InvalidPrivateKey,

    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Builds a Rustls `ServerConfig` configured with ALPN (h2, http/1.1) and dynamic resolver.
pub fn create_server_config(
    resolver: Arc<DynamicCertResolver>,
) -> Result<ServerConfig, TlsConfigError> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];

    Ok(config)
}

/// Parses PEM certificate chain and private key into a Rustls `CertifiedKey`.
pub fn parse_certified_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<CertifiedKey>, TlsConfigError> {
    // Parse certificates
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsConfigError::InvalidCertificate)?;

    if certs.is_empty() {
        return Err(TlsConfigError::InvalidCertificate);
    }

    // Parse private key
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|_| TlsConfigError::InvalidPrivateKey)?
        .ok_or(TlsConfigError::InvalidPrivateKey)?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|_| TlsConfigError::InvalidPrivateKey)?;

    let certified_key = CertifiedKey::new(certs, signing_key);
    Ok(Arc::new(certified_key))
}
