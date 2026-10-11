//! Secure on-disk certificate and account credential storage.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use thiserror::Error;
use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;
use x509_parser::prelude::*;

/// Storage errors.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("filesystem error on '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// Disk store for ACME account credentials and certificates.
#[derive(Debug, Clone)]
pub struct CertStore {
    base_dir: PathBuf,
}

impl CertStore {
    /// Creates a store with the specified base directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = base_dir.into();
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|e| StoreError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
        }
        Ok(Self { base_dir: path })
    }

    /// Path to the unified certificate chain file (default or named domain).
    pub fn cert_path(&self) -> PathBuf {
        self.base_dir.join("fullchain.pem")
    }

    /// Path to the unified private key file (default or named domain).
    pub fn key_path(&self) -> PathBuf {
        self.base_dir.join("privkey.pem")
    }

    /// Path to a specific certificate chain file for a given domain/apex.
    pub fn cert_path_for(&self, name: &str) -> PathBuf {
        let clean = name.trim().trim_start_matches("*.").to_lowercase();
        self.base_dir.join(format!("{}.fullchain.pem", clean))
    }

    /// Path to a specific private key file for a given domain/apex.
    pub fn key_path_for(&self, name: &str) -> PathBuf {
        let clean = name.trim().trim_start_matches("*.").to_lowercase();
        self.base_dir.join(format!("{}.privkey.pem", clean))
    }

    /// Path to the ACME account credentials file.
    pub fn account_path(&self) -> PathBuf {
        self.base_dir.join("account.json")
    }

    /// Configured renewal threshold in seconds (default 30 days, or overridden via PENIK_RENEWAL_THRESHOLD_SECS).
    pub fn renewal_threshold_secs() -> u64 {
        std::env::var("PENIK_RENEWAL_THRESHOLD_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30 * 86400)
    }

    /// Checks if a certificate in PEM format has at least `min_remaining_secs` remaining before expiry.
    pub fn is_cert_pem_valid(cert_pem: &str, min_remaining_secs: u64) -> bool {
        for pem in Pem::iter_from_buffer(cert_pem.as_bytes()).flatten() {
            if pem.label == "CERTIFICATE" {
                if let Ok((_, x509)) = X509Certificate::from_der(&pem.contents) {
                    let not_after = x509.validity().not_after.timestamp();
                    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(d) => d.as_secs() as i64,
                        Err(_) => return false,
                    };
                    return (not_after - now) > min_remaining_secs as i64;
                }
            }
        }
        false
    }

    /// Checks if a certificate in PEM format covers the given domain and has at least `min_remaining_secs` remaining.
    pub fn cert_pem_covers_domain(cert_pem: &str, domain: &str, min_remaining_secs: u64) -> bool {
        let domain_clean = domain.trim().trim_start_matches("*.").to_lowercase();
        for pem in Pem::iter_from_buffer(cert_pem.as_bytes()).flatten() {
            if pem.label == "CERTIFICATE" {
                if let Ok((_, x509)) = X509Certificate::from_der(&pem.contents) {
                    let not_after = x509.validity().not_after.timestamp();
                    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(d) => d.as_secs() as i64,
                        Err(_) => return false,
                    };
                    if (not_after - now) <= min_remaining_secs as i64 {
                        return false;
                    }

                    // 1. Check SAN extension
                    if let Ok(Some(san_ext)) = x509.subject_alternative_name() {
                        for name in &san_ext.value.general_names {
                            if let GeneralName::DNSName(dns) = name {
                                let dns_lower = dns.to_lowercase();
                                if dns_lower == domain_clean
                                    || crate::caddyfile::cluster::matches_site_address(&dns_lower, &domain_clean)
                                    || (dns_lower.starts_with("*.") && domain_clean.ends_with(&dns_lower[1..]))
                                {
                                    return true;
                                }
                            }
                        }
                    }

                    // 2. Check Common Name (CN)
                    for rdn in x509.subject().iter_rdn() {
                        for attr in rdn.iter() {
                            if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                                if let Ok(cn) = attr.as_str() {
                                    let cn_lower = cn.to_lowercase();
                                    if cn_lower == domain_clean
                                        || crate::caddyfile::cluster::matches_site_address(&cn_lower, &domain_clean)
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Checks if a valid, non-expired certificate and key are present on disk.
    pub fn has_certificate(&self) -> bool {
        let threshold = Self::renewal_threshold_secs();
        if let Ok(pem) = self.load_certificate() {
            if Self::is_cert_pem_valid(&pem, threshold) && self.key_path().exists() {
                return true;
            }
        }
        if let Ok(all) = self.load_all_certificates() {
            for c in all {
                if Self::is_cert_pem_valid(&c.cert_pem, threshold) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if a valid, non-expired certificate covering the domain exists on disk.
    pub fn has_certificate_for(&self, name: &str) -> bool {
        let threshold = Self::renewal_threshold_secs();
        let clean = name.trim().trim_start_matches("*.").to_lowercase();
        let apex = crate::caddyfile::cluster::extract_apex_domain(&clean);

        let candidate_paths = [
            self.cert_path_for(&clean),
            self.cert_path_for(&apex),
            self.cert_path(),
        ];

        for path in &candidate_paths {
            if path.exists() {
                if let Ok(pem) = fs::read_to_string(path) {
                    if Self::cert_pem_covers_domain(&pem, &clean, threshold) {
                        let key_path = if *path == self.cert_path() {
                            self.key_path()
                        } else if path.ends_with(format!("{}.fullchain.pem", clean)) {
                            self.key_path_for(&clean)
                        } else {
                            self.key_path_for(&apex)
                        };
                        if key_path.exists() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Saves private key with strict 0600 file permissions for a specific domain name.
    pub fn save_named_private_key(&self, name: &str, key_pem: &str) -> Result<(), StoreError> {
        let path = self.key_path_for(name);
        Self::write_secure_file(&path, key_pem)
    }

    /// Saves certificate chain for a specific domain name.
    pub fn save_named_certificate(&self, name: &str, cert_pem: &str) -> Result<(), StoreError> {
        let path = self.cert_path_for(name);
        fs::write(&path, cert_pem).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(())
    }

    /// Helper writing file with 0600 permissions.
    fn write_secure_file(path: &PathBuf, content: &str) -> Result<(), StoreError> {
        let mut file = File::create(path).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file
                .metadata()
                .map_err(|e| StoreError::Io {
                    path: path.display().to_string(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms).map_err(|e| StoreError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
        }

        file.write_all(content.as_bytes()).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        Ok(())
    }

    /// Saves private key with strict 0600 file permissions.
    pub fn save_private_key(&self, key_pem: &str) -> Result<(), StoreError> {
        Self::write_secure_file(&self.key_path(), key_pem)
    }

    /// Saves certificate chain.
    pub fn save_certificate(&self, cert_pem: &str) -> Result<(), StoreError> {
        let path = self.cert_path();
        fs::write(&path, cert_pem).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(())
    }

    /// Saves ACME account JSON with 0600 permissions.
    pub fn save_account(&self, account_json: &str) -> Result<(), StoreError> {
        let path = self.account_path();
        let mut file = File::create(&path).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file
                .metadata()
                .map_err(|e| StoreError::Io {
                    path: path.display().to_string(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms).map_err(|e| StoreError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
        }

        file.write_all(account_json.as_bytes())
            .map_err(|e| StoreError::Io {
                path: path.display().to_string(),
                source: e,
            })?;

        Ok(())
    }

    /// Loads the certificate chain PEM as string.
    pub fn load_certificate(&self) -> Result<String, StoreError> {
        let path = self.cert_path();
        fs::read_to_string(&path).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            source: e,
        })
    }

    /// Loads the private key PEM as string.
    pub fn load_private_key(&self) -> Result<String, StoreError> {
        let path = self.key_path();
        fs::read_to_string(&path).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            source: e,
        })
    }

    /// Loads the account JSON, if it exists.
    pub fn load_account(&self) -> Option<String> {
        fs::read_to_string(self.account_path()).ok()
    }

    /// Loads all available certificate and private key pairs from disk.
    pub fn load_all_certificates(&self) -> Result<Vec<LoadedCert>, StoreError> {
        let mut list = Vec::new();

        // 1. Default fullchain.pem / privkey.pem if present
        if self.cert_path().exists() && self.key_path().exists() {
            if let (Ok(cert), Ok(key)) = (self.load_certificate(), self.load_private_key()) {
                list.push(LoadedCert {
                    name: None,
                    cert_pem: cert,
                    key_pem: key,
                });
            }
        }

        // 2. Named *.fullchain.pem / *.privkey.pem
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                    if let Some(prefix) = file_name.strip_suffix(".fullchain.pem") {
                        if !prefix.is_empty() {
                            let key_name = format!("{}.privkey.pem", prefix);
                            let key_path = self.base_dir.join(key_name);
                            if key_path.exists() {
                                if let (Ok(cert), Ok(key)) = (fs::read_to_string(&path), fs::read_to_string(&key_path)) {
                                    list.push(LoadedCert {
                                        name: Some(prefix.to_string()),
                                        cert_pem: cert,
                                        key_pem: key,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(list)
    }
}

/// A certificate and private key pair loaded from disk, optionally associated with an apex or domain name.
#[derive(Debug, Clone)]
pub struct LoadedCert {
    /// Apex or domain name if this is a named certificate (e.g. "penik.ru"), or None for default fullchain.pem.
    pub name: Option<String>,
    pub cert_pem: String,
    pub key_pem: String,
}
