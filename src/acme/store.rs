//! Secure on-disk certificate and account credential storage.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
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

    /// Path to the unified certificate chain file.
    pub fn cert_path(&self) -> PathBuf {
        self.base_dir.join("fullchain.pem")
    }

    /// Path to the unified private key file.
    pub fn key_path(&self) -> PathBuf {
        self.base_dir.join("privkey.pem")
    }

    /// Path to the ACME account credentials file.
    pub fn account_path(&self) -> PathBuf {
        self.base_dir.join("account.json")
    }

    /// Checks if a valid certificate and key are present on disk.
    pub fn has_certificate(&self) -> bool {
        self.cert_path().exists() && self.key_path().exists()
    }

    /// Saves private key with strict 0600 file permissions.
    pub fn save_private_key(&self, key_pem: &str) -> Result<(), StoreError> {
        let path = self.key_path();
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

        file.write_all(key_pem.as_bytes())
            .map_err(|e| StoreError::Io {
                path: path.display().to_string(),
                source: e,
            })?;

        Ok(())
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
}
