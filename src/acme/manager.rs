//! High-level ACME order and renewal manager.

use std::path::PathBuf;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
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
    /// Custom ACME directory URL (e.g. for Pebble or local ACME servers).
    pub directory_url: Option<String>,
    /// Optional custom Root CA certificate path (e.g. for Pebble minica.pem).
    pub root_ca: Option<PathBuf>,
    /// Cloudflare DNS propagation delay in seconds (defaults to 60).
    pub propagation_secs: u64,
}

/// Manages certificate ordering, challenge resolution, and renewals.
pub struct AcmeManager {
    config: AcmeConfig,
    store: CertStore,
    alpn_registry: AlpnChallengeRegistry,
    cf_dns: Option<CloudflareDns>,
    order_lock: tokio::sync::Mutex<()>,
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
            order_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Cleans up dangling `_acme-challenge.*` TXT records for all site apex domains.
    pub async fn clean_stale_challenge_records(&self, site_domains: &[String]) {
        if let Some(cf) = &self.cf_dns {
            let mut apexes = Vec::new();
            for d in site_domains {
                apexes.push(extract_apex_domain(d));
            }
            cf.clean_stale_challenge_records(&apexes).await;
        }
    }

    /// Accessor for the active ALPN challenge registry.
    pub fn alpn_registry(&self) -> &AlpnChallengeRegistry {
        &self.alpn_registry
    }

    /// Accessor for the certificate store.
    pub fn store(&self) -> &CertStore {
        &self.store
    }

    fn account_builder(&self) -> Result<instant_acme::AccountBuilder, AcmeError> {
        if let Some(ca_path) = &self.config.root_ca {
            instant_acme::Account::builder_with_root(ca_path).map_err(AcmeError::InstantAcme)
        } else {
            instant_acme::Account::builder().map_err(AcmeError::InstantAcme)
        }
    }

    /// Obtains an active ACME account (loading saved credentials or creating a new account).
    async fn get_or_create_account(&self) -> Result<Account, AcmeError> {
        let directory_url = if let Some(custom_url) = &self.config.directory_url {
            custom_url.clone()
        } else if self.config.staging {
            LetsEncrypt::Staging.url().to_string()
        } else {
            LetsEncrypt::Production.url().to_string()
        };

        if let Some(account_json) = self.store.load_account() {
            if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&account_json) {
                if let Ok(builder) = self.account_builder() {
                    if let Ok(account) = builder.from_credentials(creds).await {
                        return Ok(account);
                    }
                }
            }
        }

        info!(email = %self.config.email, directory_url = %directory_url, "creating new ACME account");
        let contact = format!("mailto:{}", self.config.email);
        let builder = self.account_builder()?;
        let (account, creds) = builder
            .create(
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

        // Mutual exclusion: prevent concurrent ensure_certificates triggers (inotify / SIGHUP / periodic timer)
        let _guard = match self.order_lock.try_lock() {
            Ok(g) => g,
            Err(_) => {
                info!("certificate order already in progress, skipping concurrent trigger");
                return Ok(());
            }
        };

        // Check if certificates already exist on disk covering the domains
        let all_exist = site_domains.iter().all(|d| self.store.has_certificate_for(d));
        if all_exist {
            info!("valid certificates already exist on disk for all domains, skipping ACME order");
            return Ok(());
        }

        let sans = if self.cf_dns.is_some() {
            consolidate_sans(site_domains)
        } else {
            // Wildcard certificates cannot be validated via TLS-ALPN-01; use exact domains
            let mut set = std::collections::BTreeSet::new();
            for d in site_domains {
                let trimmed = d.trim().to_lowercase();
                if !trimmed.is_empty() && !trimmed.starts_with("*.") {
                    set.insert(trimmed);
                }
            }
            set.into_iter().collect()
        };
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
        let account = self.get_or_create_account().await?;

        let identifiers: Vec<Identifier> = sans
            .iter()
            .map(|s| Identifier::Dns(s.clone()))
            .collect();

        let new_order = NewOrder::new(&identifiers);
        let mut order = account.new_order(&new_order).await?;
        let mut created_cf_records: Vec<(String, String)> = Vec::new(); // (zone_id, record_id)
        let mut chosen_challenges: std::collections::HashMap<String, ChallengeType> =
            std::collections::HashMap::new();

        // Phase 1: Provision all challenge responses (DNS-01 TXT records or TLS-ALPN-01)
        let mut authz_iter = order.authorizations();
        while let Some(authz_res) = authz_iter.next().await {
            let mut authz = authz_res?;
            let domain = authz.identifier().to_string();
            let is_wildcard = domain.starts_with("*.");

            // Determine challenge strategy: DNS-01 or TLS-ALPN-01
            let mut use_dns01 = false;
            let mut cf_zone_res = None;

            if let Some(cf) = &self.cf_dns {
                let apex = extract_apex_domain(&domain);
                match cf.get_zone_id(&apex).await {
                    Ok(zone_id) => {
                        use_dns01 = true;
                        cf_zone_res = Some(zone_id);
                    }
                    Err(crate::acme::dns_cloudflare::CloudflareError::ZoneNotFound(_)) => {
                        if is_wildcard {
                            warn!(
                                domain = %domain,
                                apex = %apex,
                                "wildcard domain has no Cloudflare DNS zone; TLS-ALPN-01 cannot issue wildcards, omitting DNS-01"
                            );
                            return Err(AcmeError::NoSupportedChallenge(format!(
                                "wildcard domain '{}' has no Cloudflare DNS zone",
                                domain
                            )));
                        } else {
                            info!(
                                domain = %domain,
                                apex = %apex,
                                "Cloudflare zone not found for exact domain, falling back to TLS-ALPN-01 challenge"
                            );
                            use_dns01 = false;
                        }
                    }
                    Err(e) => {
                        if is_wildcard {
                            return Err(AcmeError::Cloudflare(e));
                        } else {
                            warn!(
                                domain = %domain,
                                error = %e,
                                "Cloudflare API error for exact domain, attempting TLS-ALPN-01 fallback"
                            );
                            use_dns01 = false;
                        }
                    }
                }
            } else if is_wildcard {
                return Err(AcmeError::NoSupportedChallenge(format!(
                    "domain '{}' requires DNS-01 but Cloudflare credentials are not configured",
                    domain
                )));
            }

            if use_dns01 {
                let cf = self.cf_dns.as_ref().unwrap();
                let zone_id = cf_zone_res.unwrap();

                let challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| AcmeError::NoSupportedChallenge(domain.clone()))?;

                let key_auth = challenge.key_authorization();
                let clean_domain = domain.trim_start_matches("*.");
                let record_name = format!("_acme-challenge.{}", clean_domain);
                let digest_b64 = BASE64_URL_SAFE_NO_PAD.encode(key_auth.digest());

                let record_id = cf
                    .create_txt_record(&zone_id, &record_name, &digest_b64)
                    .await?;
                created_cf_records.push((zone_id, record_id));
                chosen_challenges.insert(domain, ChallengeType::Dns01);
            } else {
                // Use TLS-ALPN-01
                let challenge = authz
                    .challenge(ChallengeType::TlsAlpn01)
                    .ok_or_else(|| AcmeError::NoSupportedChallenge(domain.clone()))?;

                let key_auth = challenge.key_authorization();
                self.alpn_registry
                    .register_challenge(&domain, key_auth.as_str())
                    .map_err(|e| AcmeError::NoSupportedChallenge(format!("ALPN registration: {e}")))?;
                chosen_challenges.insert(domain, ChallengeType::TlsAlpn01);
            }
        }

        // Wait once for DNS propagation across nameservers if any DNS-01 challenges were provisioned
        if !created_cf_records.is_empty() && self.config.propagation_secs > 0 {
            info!(
                seconds = self.config.propagation_secs,
                count = created_cf_records.len(),
                "waiting for DNS propagation before notifying ACME server..."
            );
            tokio::time::sleep(std::time::Duration::from_secs(self.config.propagation_secs)).await;
        }

        // Phase 2: Notify ACME server that challenges are ready
        let mut authz_iter = order.authorizations();
        while let Some(authz_res) = authz_iter.next().await {
            let mut authz = authz_res?;
            let domain = authz.identifier().to_string();

            let challenge_type = chosen_challenges
                .get(&domain)
                .copied()
                .unwrap_or(ChallengeType::TlsAlpn01);

            let mut challenge = authz
                .challenge(challenge_type)
                .ok_or_else(|| AcmeError::NoSupportedChallenge(domain.clone()))?;

            challenge.set_ready().await?;
        }

        // Phase 3: Wait for order to become Ready
        let ready_res = order.poll_ready(&RetryPolicy::default()).await;

        // Cleanup temporary records and challenges regardless of outcome
        for (zone_id, record_id) in &created_cf_records {
            if let Some(cf) = &self.cf_dns {
                let _ = cf.delete_txt_record(zone_id, record_id).await;
            }
        }
        for d in sans {
            self.alpn_registry.remove_challenge(d);
        }

        let ready_status = ready_res?;
        if ready_status != OrderStatus::Ready {
            return Err(AcmeError::OrderFailed(ready_status));
        }

        // Finalize order with rcgen (returns private key PEM)
        let key_pem = order.finalize().await?;

        // Download signed certificate chain
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

        // Save unified fallback certificates
        let _ = self.store.save_certificate(&cert_chain_pem);
        let _ = self.store.save_private_key(&key_pem);

        // Save named certificates for all apex domains covered by this order
        let mut apexes = std::collections::BTreeSet::new();
        for s in sans {
            apexes.insert(extract_apex_domain(s));
        }
        if apexes.is_empty() {
            apexes.insert("default".to_string());
        }
        for apex in apexes {
            let _ = self.store.save_named_certificate(&apex, &cert_chain_pem);
            let _ = self.store.save_named_private_key(&apex, &key_pem);
        }

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
            // Check if all domains in this apex group are already covered by valid certificates
            let all_covered = domains.iter().all(|d| self.store.has_certificate_for(d));
            if all_covered {
                info!(
                    apex = %apex,
                    domains = ?domains,
                    "all domains in apex group already covered by valid certificates, skipping order"
                );
                continue;
            }

            let sans = if self.cf_dns.is_some() {
                consolidate_sans(&domains)
            } else {
                domains.iter().filter(|s| !s.starts_with("*.")).cloned().collect()
            };
            info!(apex = %apex, sans = ?sans, "ordering partitioned certificate for apex domain");
            if let Err(e) = self.order_certificate(&sans).await {
                error!(apex = %apex, error = %e, "failed to issue certificate for apex domain");
            }
        }

        Ok(())
    }
}
