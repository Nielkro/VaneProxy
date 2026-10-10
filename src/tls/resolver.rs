//! Dynamic SNI-based TLS certificate resolver with hot-reloading support.

use std::sync::Arc;
use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Dynamic server certificate resolver supporting hot-swapping without restarting.
#[derive(Debug, Default)]
pub struct DynamicCertResolver {
    active_key: Arc<ArcSwap<Option<Arc<CertifiedKey>>>>,
}

impl DynamicCertResolver {
    /// Creates a new resolver with an optional initial certificate.
    pub fn new(initial: Option<Arc<CertifiedKey>>) -> Self {
        Self {
            active_key: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    /// Atomically updates the active certificate key.
    pub fn set_certified_key(&self, key: Arc<CertifiedKey>) {
        self.active_key.store(Arc::new(Some(key)));
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.active_key.load().as_ref().clone()
    }
}
