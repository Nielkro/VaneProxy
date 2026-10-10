//! Cloudflare DNS-01 API client for ACME challenge record management.

use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors arising from Cloudflare DNS API operations.
#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("failed to read credentials file '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("no Cloudflare API token provided or found in config")]
    MissingToken,

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Cloudflare API returned error: {message}")]
    Api { message: String },

    #[error("zone not found for apex domain '{0}'")]
    ZoneNotFound(String),
}

/// Cloudflare DNS client for ACME DNS-01 challenges.
#[derive(Debug, Clone)]
pub struct CloudflareDns {
    pub api_token: String,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Option<Vec<CfErrorItem>>,
}

#[derive(Debug, Deserialize)]
struct CfErrorItem {
    message: String,
}

#[derive(Debug, Deserialize)]
struct CfZone {
    id: String,
}

#[derive(Debug, Serialize)]
struct CreateDnsRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CreateDnsRecordResponse {
    id: String,
}

impl CloudflareDns {
    /// Creates a new client with the given API token.
    pub fn new(api_token: impl Into<String>) -> Self {
        Self {
            api_token: api_token.into(),
            client: reqwest::Client::builder().build().unwrap_or_default(),
        }
    }

    /// Loads the Cloudflare API token from a credentials file (e.g. `cloudflare.ini`) or environment.
    pub fn from_file_or_env(path: Option<&Path>) -> Result<Self, CloudflareError> {
        if let Some(p) = path {
            if p.exists() {
                let content = fs::read_to_string(p).map_err(|e| CloudflareError::Io {
                    path: p.display().to_string(),
                    source: e,
                })?;
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = trimmed.split_once('=') {
                        let key = k.trim();
                        let val = v.trim().trim_matches('"').trim_matches('\'');
                        if key == "dns_cloudflare_api_token" || key == "cloudflare_api_token" || key == "api_token" {
                            return Ok(Self::new(val));
                        }
                    }
                }
            }
        }

        if let Ok(token) = std::env::var("CLOUDFLARE_API_TOKEN") {
            if !token.trim().is_empty() {
                return Ok(Self::new(token.trim()));
            }
        }

        Err(CloudflareError::MissingToken)
    }

    /// Finds the Zone ID for an apex domain (e.g. `slavchat.ru`).
    pub async fn get_zone_id(&self, apex_domain: &str) -> Result<String, CloudflareError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            apex_domain.trim().to_lowercase()
        );

        let res = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .json::<CfResponse<Vec<CfZone>>>()
            .await?;

        if !res.success {
            let msg = res
                .errors
                .and_then(|errs| errs.into_iter().next())
                .map(|e| e.message)
                .unwrap_or_else(|| "unknown API error".to_string());
            return Err(CloudflareError::Api { message: msg });
        }

        let zones = res.result.unwrap_or_default();
        zones
            .into_iter()
            .next()
            .map(|z| z.id)
            .ok_or_else(|| CloudflareError::ZoneNotFound(apex_domain.to_string()))
    }

    /// Creates a temporary TXT record `_acme-challenge.<domain>` with the challenge value.
    pub async fn create_txt_record(
        &self,
        zone_id: &str,
        record_name: &str,
        content: &str,
    ) -> Result<String, CloudflareError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        );

        let payload = CreateDnsRecordRequest {
            record_type: "TXT",
            name: record_name,
            content,
            ttl: 60,
        };

        let res = self
            .client
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&payload)
            .send()
            .await?
            .json::<CfResponse<CreateDnsRecordResponse>>()
            .await?;

        if !res.success {
            let msg = res
                .errors
                .and_then(|errs| errs.into_iter().next())
                .map(|e| e.message)
                .unwrap_or_else(|| "unknown API error".to_string());
            return Err(CloudflareError::Api { message: msg });
        }

        res.result
            .map(|r| r.id)
            .ok_or_else(|| CloudflareError::Api {
                message: "missing record id in response".to_string(),
            })
    }

    /// Deletes a temporary TXT challenge record.
    pub async fn delete_txt_record(
        &self,
        zone_id: &str,
        record_id: &str,
    ) -> Result<(), CloudflareError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            zone_id, record_id
        );

        let res = self
            .client
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .json::<CfResponse<serde_json::Value>>()
            .await?;

        if !res.success {
            let msg = res
                .errors
                .and_then(|errs| errs.into_iter().next())
                .map(|e| e.message)
                .unwrap_or_else(|| "unknown API error".to_string());
            return Err(CloudflareError::Api { message: msg });
        }

        Ok(())
    }
}
