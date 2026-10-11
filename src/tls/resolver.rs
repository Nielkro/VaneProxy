use std::collections::HashMap;
use std::sync::Arc;
use arc_swap::ArcSwap;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::acme::alpn_challenge::AlpnChallengeRegistry;
use crate::caddyfile::cluster::matches_site_address;

/// Dynamic server certificate resolver supporting multiple domains, wildcards, and TLS-ALPN-01.
#[derive(Debug, Default)]
pub struct DynamicCertResolver {
    default_key: Arc<ArcSwap<Option<Arc<CertifiedKey>>>>,
    domain_keys: Arc<ArcSwap<HashMap<String, Arc<CertifiedKey>>>>,
    alpn_registry: Option<Arc<AlpnChallengeRegistry>>,
}

impl DynamicCertResolver {
    /// Creates a new resolver with an optional initial certificate.
    pub fn new(initial: Option<Arc<CertifiedKey>>) -> Self {
        Self {
            default_key: Arc::new(ArcSwap::from_pointee(initial)),
            domain_keys: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            alpn_registry: None,
        }
    }

    /// Creates a new resolver with an optional initial certificate and an ALPN challenge registry.
    pub fn with_alpn_registry(
        initial: Option<Arc<CertifiedKey>>,
        alpn_registry: Arc<AlpnChallengeRegistry>,
    ) -> Self {
        Self {
            default_key: Arc::new(ArcSwap::from_pointee(initial)),
            domain_keys: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            alpn_registry: Some(alpn_registry),
        }
    }

    /// Atomically updates the default fallback certificate.
    pub fn set_certified_key(&self, key: Arc<CertifiedKey>) {
        self.default_key.store(Arc::new(Some(key)));
    }

    /// Registers a certificate for a list of domain names (exact and wildcards).
    pub fn register_certified_key(&self, domains: &[String], key: Arc<CertifiedKey>) {
        let mut map = (**self.domain_keys.load()).clone();
        for d in domains {
            let clean = d.trim().to_lowercase();
            if !clean.is_empty() {
                map.insert(clean, key.clone());
            }
        }
        // Also update default if empty
        if self.default_key.load().is_none() {
            self.default_key.store(Arc::new(Some(key)));
        }
        self.domain_keys.store(Arc::new(map));
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // 0. Check if this connection is an ACME TLS-ALPN-01 challenge probe
        if let Some(registry) = &self.alpn_registry {
            let alpn_matches = client_hello
                .alpn()
                .map(|mut it| it.any(|proto| proto == b"acme-tls/1"))
                .unwrap_or(false);

            if alpn_matches {
                if let Some(server_name) = client_hello.server_name() {
                    if let Some(challenge) = registry.get_challenge(server_name) {
                        let cert = CertificateDer::from(challenge.cert_der);
                        let key_der = rustls_pki_types::PrivateKeyDer::try_from(challenge.key_der).ok()?;
                        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der).ok()?;
                        return Some(Arc::new(CertifiedKey::new(vec![cert], signing_key)));
                    }
                }
            }
        }

        // 1. Check exact match or wildcard match for SNI
        if let Some(sni) = client_hello.server_name() {
            let sni_lower = sni.trim().to_lowercase();
            let keys = self.domain_keys.load();

            // 1a. Exact match
            if let Some(k) = keys.get(&sni_lower) {
                return Some(k.clone());
            }

            // 1b. Wildcard match (*.domain.com)
            for (pattern, k) in keys.iter() {
                if matches_site_address(pattern, &sni_lower) {
                    return Some(k.clone());
                }
            }
        }

        // 2. Fallback to default certificate
        self.default_key.load().as_ref().clone()
    }
}
