//! Ephemeral TLS-ALPN-01 challenge certificate manager (RFC 8737).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Error generating or retrieving ALPN challenge certificates.
#[derive(Debug, Error)]
pub enum AlpnChallengeError {
    #[error("rcgen certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
}

/// An ephemeral certificate and private key DER bytes for TLS-ALPN-01 challenge response.
#[derive(Debug, Clone)]
pub struct AlpnChallengeCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// In-memory registry of active TLS-ALPN-01 challenges.
#[derive(Debug, Clone, Default)]
pub struct AlpnChallengeRegistry {
    challenges: Arc<RwLock<HashMap<String, AlpnChallengeCert>>>,
}

impl AlpnChallengeRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a TLS-ALPN-01 challenge for the given domain using its key authorization.
    ///
    /// Generates a self-signed certificate containing the critical extension
    /// `id-pe-acmeIdentifier` (OID 1.3.6.1.5.5.7.1.31) with SHA-256 of key authorization (RFC 8737).
    pub fn register_challenge(
        &self,
        domain: &str,
        key_authorization: &str,
    ) -> Result<(), AlpnChallengeError> {
        // Calculate SHA-256 digest of key authorization
        let mut hasher = Sha256::new();
        hasher.update(key_authorization.as_bytes());
        let digest = hasher.finalize();

        // Build ASN.1 OCTET STRING DER: tag 0x04, length 0x20 (32 bytes), followed by digest
        let mut octet_string_der = Vec::with_capacity(34);
        octet_string_der.push(0x04);
        octet_string_der.push(0x20);
        octet_string_der.extend_from_slice(&digest);

        // Build critical custom extension with OID 1.3.6.1.5.5.7.1.31
        let acme_oid = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
        let mut ext = CustomExtension::from_oid_content(acme_oid, octet_string_der);
        ext.set_criticality(true);

        // Generate self-signed certificate with domain in SAN
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        params.custom_extensions.push(ext);

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        let entry = AlpnChallengeCert {
            cert_der: cert.der().to_vec(),
            key_der: key_pair.serialize_der(),
        };

        let mut lock = self.challenges.write().unwrap();
        lock.insert(domain.to_lowercase(), entry);

        Ok(())
    }

    /// Retrieves an active challenge certificate for the specified domain.
    pub fn get_challenge(&self, domain: &str) -> Option<AlpnChallengeCert> {
        let lock = self.challenges.read().unwrap();
        lock.get(&domain.to_lowercase()).cloned()
    }

    /// Removes a completed or failed challenge from the registry.
    pub fn remove_challenge(&self, domain: &str) {
        let mut lock = self.challenges.write().unwrap();
        lock.remove(&domain.to_lowercase());
    }
}
