//! Secure on-disk certificate and account credential storage.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use thiserror::Error;

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

    /// Checks if a valid certificate and key are present on disk (default or named).
    pub fn has_certificate(&self) -> bool {
        (self.cert_path().exists() && self.key_path().exists())
            || self.load_all_certificates().map(|v| !v.is_empty()).unwrap_or(false)
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
    pub fn load_all_certificates(&self) -> Result<Vec<(String, String)>, StoreError> {
        let mut list = Vec::new();

        // 1. Default fullchain.pem / privkey.pem if present
        if self.cert_path().exists() && self.key_path().exists() {
            if let (Ok(cert), Ok(key)) = (self.load_certificate(), self.load_private_key()) {
                list.push((cert, key));
            }
        }

        // 2. Named *.fullchain.pem / *.privkey.pem
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                    if file_name.ends_with(".fullchain.pem") {
                        let prefix = file_name.trim_end_matches(".fullchain.pem");
                        let key_name = format!("{}.privkey.pem", prefix);
                        let key_path = self.base_dir.join(key_name);
                        if key_path.exists() {
                            if let (Ok(cert), Ok(key)) = (fs::read_to_string(&path), fs::read_to_string(&key_path)) {
                                list.push((cert, key));
                            }
                        }
                    }
                }
            }
        }

        Ok(list)
    }
}
