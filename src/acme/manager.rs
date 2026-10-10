//! High-level ACME order and renewal manager.

use std::path::PathBuf;
use std::time::Duration;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair};
use thiserror::Error;
use tracing::{error, info, warn};

use crate::acme::alpn_challenge::AlpnChallengeRegistry;
use crate::acme::dns_cloudflare::CloudflareDns;
use crate::acme::store::CertStore;
use crate::caddyfile::cluster::{consolidate_sans, extract_apex_domain};

/// Errors encountered during ACME management.
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    InstantAcme(#[from] instant_acme::Error),

    #[error("rcgen key generation or CSR error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("certificate storage error: {0}")]
    Store(#[from] crate::acme::store::StoreError),

    #[error("cloudflare DNS error: {0}")]
    Cloudflare(#[from] crate::acme::dns_cloudflare::CloudflareError),

    #[error("no supported challenge found for identifier '{0}'")]
    NoSupportedChallenge(String),

    #[error("ACME order failed with status: {0:?}")]
    OrderFailed(OrderStatus),
}

/// Configuration for ACME automation.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// Account contact email.
    pub email: String,
    /// Whether to use Let's Encrypt Staging environment.
    pub staging: bool,
    /// Path to certificate storage directory.
    pub storage_dir: PathBuf,
    /// Path to cloudflare.ini, if configured.
    pub cloudflare_credentials: Option<PathBuf>,
    /// Direct Cloudflare API token, if configured.
    pub cloudflare_token: Option<String>,
}

/// Manages certificate ordering, challenge resolution, and renewals.
pub struct AcmeManager {
    config: AcmeConfig,
    store: CertStore,
    alpn_registry: AlpnChallengeRegistry,
    cf_dns: Option<CloudflareDns>,
}

impl AcmeManager {
    /// Creates a new ACME manager instance.
    pub fn new(config: AcmeConfig, alpn_registry: AlpnChallengeRegistry) -> Result<Self, AcmeError> {
        let store = CertStore::new(&config.storage_dir)?;

        let cf_dns = if let Some(token) = &config.cloudflare_token {
            Some(CloudflareDns::new(token))
        } else if let Some(cred_path) = &config.cloudflare_credentials {
            CloudflareDns::from_file_or_env(Some(cred_path)).ok()
        } else {
            CloudflareDns::from_file_or_env(None).ok()
        };

        Ok(Self {
            config,
            store,
            alpn_registry,
            cf_dns,
        })
    }

    /// Accessor for the active ALPN challenge registry.
    pub fn alpn_registry(&self) -> &AlpnChallengeRegistry {
        &self.alpn_registry
    }

    /// Accessor for the certificate store.
    pub fn store(&self) -> &CertStore {
        &self.store
    }

    /// Obtains an active ACME account (loading saved credentials or creating a new account).
    async fn get_or_create_account(&self) -> Result<Account, AcmeError> {
        let directory_url = if self.config.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        if let Some(account_json) = self.store.load_account() {
            if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&account_json) {
                if let Ok(account) = Account::from_credentials(creds) {
                    return Ok(account);
                }
            }
        }

        info!(email = %self.config.email, staging = self.config.staging, "creating new ACME account");
        let contact = format!("mailto:{}", self.config.email);
        let (account, creds) = Account::create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await?;

        if let Ok(json) = serde_json::to_string_pretty(&creds) {
            let _ = self.store.save_account(&json);
        }

        Ok(account)
    }

    /// Ensures that valid certificates exist for all configured site domains.
    ///
    /// Consolidates domains into a unified SAN list and submits an ACME order.
    /// If the unified multi-SAN order fails, partitions by apex domain to isolate errors.
    pub async fn ensure_certificates(&self, site_domains: &[String]) -> Result<(), AcmeError> {
        if site_domains.is_empty() {
            return Ok(());
        }

        let sans = consolidate_sans(site_domains);
        info!(sans = ?sans, "consolidated SANs for ACME order");

        // Attempt single unified order first
        match self.order_certificate(&sans).await {
            Ok(()) => {
                info!("unified multi-SAN certificate issued and stored successfully");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "consolidated multi-SAN order failed, activating partitioning fallback");
                self.order_partitioned(site_domains).await
            }
        }
    }

    /// Orders a certificate for the given SAN list.
    async fn order_certificate(&self, sans: &[String]) -> Result<(), AcmeError> {
        let mut account = self.get_or_create_account().await?;

        let identifiers: Vec<Identifier> = sans
            .iter()
            .map(|s| Identifier::Dns(s.clone()))
            .collect();

        let mut order = account.new_order(&NewOrder { identifiers: &identifiers }).await?;
        let mut created_cf_records: Vec<(String, String)> = Vec::new(); // (zone_id, record_id)

        // Process authorizations
        let mut authz_list = order.authorizations().await?;
        for authz in &mut authz_list {
            match authz.status {
                AuthorizationStatus::Pending => {}
                _ => continue,
            }

            let domain = match &authz.identifier {
                Identifier::Dns(d) => d.clone(),
            };

            let is_wildcard = domain.starts_with("*.");

            // Select challenge
            if is_wildcard || self.cf_dns.is_some() {
                // Use DNS-01
                let cf = self.cf_dns.as_ref().ok_or_else(|| {
                    AcmeError::NoSupportedChallenge(format!(
                        "domain '{}' requires DNS-01 but Cloudflare credentials are not configured",
                        domain
                    ))
                })?;

                let challenge = authz
                    .challenges
                    .iter()
                    .find(|c| c.r#type == ChallengeType::Dns01)
                    .ok_or_else(|| AcmeError::NoSupportedChallenge(domain.clone()))?;

                let key_auth = order.key_authorization(challenge);
                let apex = extract_apex_domain(&domain);
                let zone_id = cf.get_zone_id(&apex).await?;

                let clean_domain = domain.trim_start_matches("*.");
                let record_name = format!("_acme-challenge.{}", clean_domain);

                let record_id = cf
                    .create_txt_record(&zone_id, &record_name, key_auth.digest())
                    .await?;
                created_cf_records.push((zone_id, record_id));

                // Inform ACME server that DNS challenge is ready
                order.set_challenge_ready(&challenge.url).await?;
            } else {
                // Use TLS-ALPN-01
                let challenge = authz
                    .challenges
                    .iter()
                    .find(|c| c.r#type == ChallengeType::TlsAlpn01)
                    .ok_or_else(|| AcmeError::NoSupportedChallenge(domain.clone()))?;

                let key_auth = order.key_authorization(challenge);
                self.alpn_registry
                    .register_challenge(&domain, key_auth.as_str())
                    .map_err(|e| AcmeError::NoSupportedChallenge(format!("ALPN registration: {e}")))?;

                order.set_challenge_ready(&challenge.url).await?;
            }
        }

        // Wait for order to become Ready
        let mut retries = 0;
        let mut order_status = order.state().status;
        while order_status == OrderStatus::Pending || order_status == OrderStatus::Processing {
            tokio::time::sleep(Duration::from_secs(2)).await;
            order_status = order.refresh().await?;
            retries += 1;
            if retries > 30 {
                break;
            }
        }

        // Cleanup temporary records and challenges
        for (zone_id, record_id) in created_cf_records {
            if let Some(cf) = &self.cf_dns {
                let _ = cf.delete_txt_record(&zone_id, &record_id).await;
            }
        }
        for d in sans {
            self.alpn_registry.remove_challenge(d);
        }

        if order_status != OrderStatus::Ready {
            return Err(AcmeError::OrderFailed(order_status));
        }

        // Finalize order with CSR
        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::new(sans.to_vec())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key_pair)?;

        order.finalize(csr.der()).await?;

        // Poll until Valid
        retries = 0;
        while order.state().status != OrderStatus::Valid {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if order.refresh().await? == OrderStatus::Valid {
                break;
            }
            retries += 1;
            if retries > 30 {
                return Err(AcmeError::OrderFailed(order.state().status));
            }
        }

        // Download certificate chain
        let cert_chain_pem = order
            .certificate()
            .await?
            .ok_or_else(|| AcmeError::OrderFailed(OrderStatus::Invalid))?;

        let key_pem = key_pair.serialize_pem();

        self.store.save_certificate(&cert_chain_pem)?;
        self.store.save_private_key(&key_pem)?;

        Ok(())
    }

    /// Partitioning fallback: orders certificates per apex domain.
    async fn order_partitioned(&self, site_domains: &[String]) -> Result<(), AcmeError> {
        let mut apex_groups: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();

        for d in site_domains {
            let apex = extract_apex_domain(d);
            apex_groups.entry(apex).or_default().push(d.clone());
        }

        for (apex, domains) in apex_groups {
            let sans = consolidate_sans(&domains);
            info!(apex = %apex, sans = ?sans, "ordering partitioned certificate for apex domain");
            if let Err(e) = self.order_certificate(&sans).await {
                error!(apex = %apex, error = %e, "failed to issue certificate for apex domain");
            }
        }

        Ok(())
    }
}
