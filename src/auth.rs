use async_trait::async_trait;
use reqwest::header::HeaderValue;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::config::UpstreamAuthConfig;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Failed to acquire token: {0}")]
    TokenAcquisition(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Invalid configuration: {0}")]
    Config(String),
}

/// Trait for upstream authentication providers
#[async_trait]
pub trait UpstreamAuth: Send + Sync {
    /// Get the authorization header value for upstream requests
    async fn get_auth_header(&self) -> Result<HeaderValue, AuthError>;

    /// Get any additional headers required for the upstream request
    async fn get_additional_headers(&self) -> Result<Vec<(String, HeaderValue)>, AuthError> {
        Ok(vec![])
    }
}

/// API Key authentication - uses a static API key
pub struct ApiKeyAuth {
    api_key: String,
}

impl ApiKeyAuth {
    pub fn new(api_key: String) -> Self {
        Self { api_key }
    }
}

#[async_trait]
impl UpstreamAuth for ApiKeyAuth {
    async fn get_auth_header(&self) -> Result<HeaderValue, AuthError> {
        HeaderValue::from_str(&self.api_key)
            .map_err(|e| AuthError::Config(format!("Invalid API key format: {}", e)))
    }
}

/// Azure AD (Entra ID) authentication with token caching
pub struct AzureAdAuth {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    scope: String,
    http_client: reqwest::Client,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    expires_in: i64,
}

impl AzureAdAuth {
    pub fn new(tenant_id: String, client_id: String, client_secret: String, scope: String) -> Self {
        Self {
            tenant_id,
            client_id,
            client_secret,
            scope,
            http_client: reqwest::Client::new(),
            cached_token: Arc::new(RwLock::new(None)),
        }
    }

    async fn fetch_token(&self) -> Result<CachedToken, AuthError> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", &self.scope),
        ];

        let response = self
            .http_client
            .post(&token_url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::TokenAcquisition(format!(
                "Azure AD token request failed: {}",
                error_text
            )));
        }

        let token_response: AzureTokenResponse = response.json().await?;

        // Add a buffer of 60 seconds before expiry to ensure we refresh in time
        let expires_at =
            chrono::Utc::now() + chrono::Duration::seconds(token_response.expires_in - 60);

        Ok(CachedToken {
            access_token: token_response.access_token,
            expires_at,
        })
    }

    async fn get_valid_token(&self) -> Result<String, AuthError> {
        // Check if we have a valid cached token
        {
            let cached = self.cached_token.read().await;
            if let Some(ref token) = *cached {
                if token.expires_at > chrono::Utc::now() {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Need to refresh the token
        let new_token = self.fetch_token().await?;
        let access_token = new_token.access_token.clone();

        {
            let mut cached = self.cached_token.write().await;
            *cached = Some(new_token);
        }

        Ok(access_token)
    }
}

#[async_trait]
impl UpstreamAuth for AzureAdAuth {
    async fn get_auth_header(&self) -> Result<HeaderValue, AuthError> {
        let token = self.get_valid_token().await?;
        let header_value = format!("Bearer {}", token);
        HeaderValue::from_str(&header_value)
            .map_err(|e| AuthError::Config(format!("Invalid token format: {}", e)))
    }
}

/// Azure CLI credential authentication - uses `az account get-access-token`
pub struct AzureCliAuth {
    scope: String,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureCliTokenResponse {
    access_token: String,
    expires_on: String,
}

impl AzureCliAuth {
    pub fn new(scope: String) -> Self {
        Self {
            scope,
            cached_token: Arc::new(RwLock::new(None)),
        }
    }

    async fn fetch_token(&self) -> Result<CachedToken, AuthError> {
        let output = tokio::process::Command::new("az")
            .args([
                "account",
                "get-access-token",
                "--scope",
                &self.scope,
                "--output",
                "json",
            ])
            .output()
            .await
            .map_err(|e| AuthError::TokenAcquisition(format!("Failed to execute az cli: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AuthError::TokenAcquisition(format!(
                "az cli failed: {}",
                stderr
            )));
        }

        let token_response: AzureCliTokenResponse = serde_json::from_slice(&output.stdout)
            .map_err(|e| {
                AuthError::TokenAcquisition(format!("Failed to parse az cli output: {}", e))
            })?;

        // Parse the expires_on timestamp (format: "2024-01-15 10:30:00.000000")
        let expires_at = chrono::NaiveDateTime::parse_from_str(
            &token_response.expires_on,
            "%Y-%m-%d %H:%M:%S.%f",
        )
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(&token_response.expires_on, "%Y-%m-%d %H:%M:%S")
        })
        .map(|dt| dt.and_utc())
        .unwrap_or_else(|_| chrono::Utc::now() + chrono::Duration::hours(1));

        // Subtract 60 seconds buffer
        let expires_at = expires_at - chrono::Duration::seconds(60);

        Ok(CachedToken {
            access_token: token_response.access_token,
            expires_at,
        })
    }

    async fn get_valid_token(&self) -> Result<String, AuthError> {
        // Check if we have a valid cached token
        {
            let cached = self.cached_token.read().await;
            if let Some(ref token) = *cached {
                if token.expires_at > chrono::Utc::now() {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Need to refresh the token
        let new_token = self.fetch_token().await?;
        let access_token = new_token.access_token.clone();

        {
            let mut cached = self.cached_token.write().await;
            *cached = Some(new_token);
        }

        Ok(access_token)
    }
}

#[async_trait]
impl UpstreamAuth for AzureCliAuth {
    async fn get_auth_header(&self) -> Result<HeaderValue, AuthError> {
        let token = self.get_valid_token().await?;
        let header_value = format!("Bearer {}", token);
        HeaderValue::from_str(&header_value)
            .map_err(|e| AuthError::Config(format!("Invalid token format: {}", e)))
    }
}

/// Create an upstream auth provider from configuration
pub fn create_upstream_auth(config: &UpstreamAuthConfig) -> Arc<dyn UpstreamAuth> {
    match config {
        UpstreamAuthConfig::ApiKey { api_key } => Arc::new(ApiKeyAuth::new(api_key.clone())),
        UpstreamAuthConfig::AzureAd {
            tenant_id,
            client_id,
            client_secret,
            scope,
        } => Arc::new(AzureAdAuth::new(
            tenant_id.clone(),
            client_id.clone(),
            client_secret.clone(),
            scope.clone(),
        )),
        UpstreamAuthConfig::AzureCli { scope } => Arc::new(AzureCliAuth::new(scope.clone())),
    }
}
