use std::collections::HashMap;
use std::sync::Arc;
use arc_swap::ArcSwap;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::acme::alpn_challenge::AlpnChallengeRegistry;
use crate::caddyfile::cluster::{extract_apex_domain, matches_site_address};

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

    /// Registers all loaded certificates into the resolver.
    ///
    /// Unnamed certificates (default `fullchain.pem`) are registered for all site domains
    /// and serve as fallback. Named certificates (e.g. `example.com.fullchain.pem`) are registered
    /// strictly for site domains that share the matching apex domain name, avoiding cross-domain
    /// certificate overwriting.
    pub fn register_loaded_certs(&self, site_domains: &[String], certs: &[crate::acme::LoadedCert]) {
        // 1. Default fallback certificates first
        for cert in certs {
            if cert.name.is_none() {
                if let Ok(ck) = crate::tls::parse_certified_key(&cert.cert_pem, &cert.key_pem) {
                    self.register_certified_key(site_domains, ck.clone());
                    self.set_certified_key(ck);
                }
            }
        }

        // 2. Named apex certificates registered strictly to their matching domains
        for cert in certs {
            if let Some(apex) = &cert.name {
                if let Ok(ck) = crate::tls::parse_certified_key(&cert.cert_pem, &cert.key_pem) {
                    let matching: Vec<String> = site_domains
                        .iter()
                        .filter(|d| {
                            let d_apex = extract_apex_domain(d);
                            d_apex.eq_ignore_ascii_case(apex)
                        })
                        .cloned()
                        .collect();

                    if !matching.is_empty() {
                        self.register_certified_key(&matching, ck.clone());
                    } else {
                        // Fallback: register apex and wildcard directly if not explicitly listed in site_domains
                        let fallback_domains = vec![apex.clone(), format!("*.{}", apex)];
                        self.register_certified_key(&fallback_domains, ck.clone());
                    }

                    if self.default_key.load().is_none() {
                        self.set_certified_key(ck);
                    }
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    #[test]
    fn test_dynamic_resolver_multi_apex_isolation() {
        let resolver = DynamicCertResolver::new(None);

        // Generate self-signed cert for example.org
        let key_org = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params_org =
            CertificateParams::new(vec!["example.org".into(), "chat.example.org".into()]).unwrap();
        let cert_org = params_org.self_signed(&key_org).unwrap();

        // Generate self-signed cert for example.com
        let key_com = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params_com =
            CertificateParams::new(vec!["example.com".into(), "test.dev.example.com".into()]).unwrap();
        let cert_com = params_com.self_signed(&key_com).unwrap();

        let certs = vec![
            crate::acme::LoadedCert {
                name: Some("example.org".to_string()),
                cert_pem: cert_org.pem(),
                key_pem: key_org.serialize_pem(),
            },
            crate::acme::LoadedCert {
                name: Some("example.com".to_string()),
                cert_pem: cert_com.pem(),
                key_pem: key_com.serialize_pem(),
            },
        ];

        let site_domains = vec![
            "chat.example.org".to_string(),
            "test.dev.example.com".to_string(),
        ];

        resolver.register_loaded_certs(&site_domains, &certs);

        let keys = resolver.domain_keys.load();
        let key_for_org = keys.get("chat.example.org").expect("must have example.org key");
        let key_for_com = keys.get("test.dev.example.com").expect("must have example.com key");

        // Verify that chat.example.org and test.dev.example.com have distinct certified keys
        assert_ne!(
            key_for_org.cert.first().unwrap().as_ref(),
            key_for_com.cert.first().unwrap().as_ref()
        );

        // Verify that chat.example.org actually got the example.org certificate
        let parsed_org_ck =
            crate::tls::parse_certified_key(&cert_org.pem(), &key_org.serialize_pem()).unwrap();
        assert_eq!(
            key_for_org.cert.first().unwrap().as_ref(),
            parsed_org_ck.cert.first().unwrap().as_ref()
        );

        // Verify that test.dev.example.com actually got the example.com certificate
        let parsed_com_ck =
            crate::tls::parse_certified_key(&cert_com.pem(), &key_com.serialize_pem()).unwrap();
        assert_eq!(
            key_for_com.cert.first().unwrap().as_ref(),
            parsed_com_ck.cert.first().unwrap().as_ref()
        );
    }
}

