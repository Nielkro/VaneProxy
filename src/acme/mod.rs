//! Native ACME v2 automation (DNS-01 & TLS-ALPN-01) and certificate lifecycle.

pub mod alpn_challenge;
pub mod dns_cloudflare;
pub mod manager;
pub mod store;

pub use alpn_challenge::{AlpnChallengeCert, AlpnChallengeRegistry};
pub use dns_cloudflare::CloudflareDns;
pub use manager::{AcmeConfig, AcmeError, AcmeManager};
pub use store::CertStore;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_cert_store_save_load_and_permissions() {
        let temp_dir = std::env::temp_dir().join(format!("penik_test_store_{}", std::process::id()));
        let store = CertStore::new(&temp_dir).expect("should create store");

        let cert_content = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n";

        store.save_certificate(cert_content).expect("should save cert");
        store.save_private_key(key_content).expect("should save key");

        assert!(store.has_certificate());
        assert_eq!(store.load_certificate().unwrap(), cert_content);
        assert_eq!(store.load_private_key().unwrap(), key_content);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(store.key_path()).expect("metadata");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_alpn_challenge_registration_and_retrieval() {
        let registry = AlpnChallengeRegistry::new();
        let domain = "test.slavchat.ru";
        let key_auth = "token123.thumbprint456";

        registry
            .register_challenge(domain, key_auth)
            .expect("should register ALPN challenge");

        let challenge = registry.get_challenge(domain).expect("should find challenge");
        assert!(!challenge.cert_der.is_empty());
        assert!(!challenge.key_der.is_empty());

        registry.remove_challenge(domain);
        assert!(registry.get_challenge(domain).is_none());
    }

    #[test]
    fn test_cloudflare_ini_parser() {
        let temp_dir = std::env::temp_dir().join(format!("penik_test_cf_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let ini_file = temp_dir.join("cloudflare.ini");

        fs::write(
            &ini_file,
            "# Cloudflare API token credentials\ndns_cloudflare_api_token = \"test_token_secret_123\"\n",
        )
        .expect("should write ini");

        let cf = CloudflareDns::from_file_or_env(Some(&ini_file)).expect("should parse ini");
        assert_eq!(cf.api_token, "test_token_secret_123");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
