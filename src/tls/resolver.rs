use std::sync::Arc;
use arc_swap::ArcSwap;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::acme::alpn_challenge::AlpnChallengeRegistry;

/// Dynamic server certificate resolver supporting hot-swapping and TLS-ALPN-01 challenges.
#[derive(Debug, Default)]
pub struct DynamicCertResolver {
    active_key: Arc<ArcSwap<Option<Arc<CertifiedKey>>>>,
    alpn_registry: Option<Arc<AlpnChallengeRegistry>>,
}

impl DynamicCertResolver {
    /// Creates a new resolver with an optional initial certificate.
    pub fn new(initial: Option<Arc<CertifiedKey>>) -> Self {
        Self {
            active_key: Arc::new(ArcSwap::from_pointee(initial)),
            alpn_registry: None,
        }
    }

    /// Creates a new resolver with an optional initial certificate and an ALPN challenge registry.
    pub fn with_alpn_registry(
        initial: Option<Arc<CertifiedKey>>,
        alpn_registry: Arc<AlpnChallengeRegistry>,
    ) -> Self {
        Self {
            active_key: Arc::new(ArcSwap::from_pointee(initial)),
            alpn_registry: Some(alpn_registry),
        }
    }

    /// Atomically updates the active certificate key.
    pub fn set_certified_key(&self, key: Arc<CertifiedKey>) {
        self.active_key.store(Arc::new(Some(key)));
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Check if this connection is an ACME TLS-ALPN-01 challenge probe
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

        self.active_key.load().as_ref().clone()
    }
}
