//! ACME (Let's Encrypt) certificate provisioning
//!
//! Handles:
//! - Account creation/loading
//! - Certificate ordering and renewal
//! - HTTP-01 challenge responses
//! - Certificate caching

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::Path as AxumPath, extract::State, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::tls::TlsError;

/// State for HTTP-01 challenge responses
#[derive(Clone, Default)]
pub struct AcmeChallengeState {
    /// Map of token -> key_authorization
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

/// ACME manager for certificate lifecycle
pub struct AcmeManager {
    account: Account,
    domains: Vec<String>,
    cache_dir: PathBuf,
    challenge_state: AcmeChallengeState,
    rustls_config: RustlsConfig,
    /// PEM-encoded private key for certificate signing
    key_pem: String,
}

impl AcmeManager {
    /// Create a new ACME manager
    pub async fn new(
        email: &str,
        domains: Vec<String>,
        directory_url: &str,
        cache_dir: &str,
    ) -> Result<Self, TlsError> {
        let cache_path = PathBuf::from(cache_dir);
        std::fs::create_dir_all(&cache_path)?;

        // Load or create ACME account
        let account = Self::load_or_create_account(email, directory_url, &cache_path).await?;

        // Load existing key or generate new one
        let key_path = cache_path.join("key.pem");
        let key_pem = if key_path.exists() {
            std::fs::read_to_string(&key_path)
                .map_err(|e| TlsError::Acme(format!("Failed to read key: {}", e)))?
        } else {
            let key_pair = KeyPair::generate()
                .map_err(|e| TlsError::Acme(format!("Failed to generate key: {}", e)))?;
            let pem = key_pair.serialize_pem();
            std::fs::write(&key_path, &pem)?;
            pem
        };

        // Initialize with cached or placeholder certificate
        let rustls_config =
            Self::load_or_create_placeholder_cert(&domains, &cache_path, &key_pem).await?;

        Ok(Self {
            account,
            domains,
            cache_dir: cache_path,
            challenge_state: AcmeChallengeState::default(),
            rustls_config,
            key_pem,
        })
    }

    async fn load_or_create_account(
        email: &str,
        directory_url: &str,
        cache_path: &Path,
    ) -> Result<Account, TlsError> {
        let account_path = cache_path.join("account.json");

        if account_path.exists() {
            // Load existing account credentials
            let credentials_json = std::fs::read_to_string(&account_path)
                .map_err(|e| TlsError::Acme(format!("Failed to read account: {}", e)))?;
            let credentials: AccountCredentials = serde_json::from_str(&credentials_json)
                .map_err(|e| TlsError::Acme(format!("Failed to parse account: {}", e)))?;

            info!("Loaded existing ACME account");
            Account::from_credentials(credentials)
                .await
                .map_err(|e| TlsError::Acme(format!("Failed to restore account: {}", e)))
        } else {
            // Create new account
            info!("Creating new ACME account for {}", email);
            let (account, credentials) = Account::create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url,
                None,
            )
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to create account: {}", e)))?;

            // Save credentials
            let credentials_json = serde_json::to_string_pretty(&credentials)
                .map_err(|e| TlsError::Acme(format!("Failed to serialize account: {}", e)))?;
            std::fs::write(&account_path, credentials_json)?;

            Ok(account)
        }
    }

    async fn load_or_create_placeholder_cert(
        domains: &[String],
        cache_path: &Path,
        key_pem: &str,
    ) -> Result<RustlsConfig, TlsError> {
        let cert_path = cache_path.join("cert.pem");
        let key_path = cache_path.join("key.pem");

        // Check if we have valid cached certificates
        if cert_path.exists() && key_path.exists() {
            match RustlsConfig::from_pem_file(&cert_path, &key_path).await {
                Ok(config) => {
                    info!("Loaded cached certificate");
                    return Ok(config);
                }
                Err(e) => {
                    warn!(
                        "Failed to load cached certificate: {}, will provision new one",
                        e
                    );
                }
            }
        }

        // Create a self-signed certificate as placeholder until ACME completes
        Self::create_placeholder_cert(domains, cache_path, key_pem).await
    }

    async fn create_placeholder_cert(
        domains: &[String],
        cache_path: &Path,
        key_pem: &str,
    ) -> Result<RustlsConfig, TlsError> {
        info!("Creating placeholder self-signed certificate");

        let key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| TlsError::Acme(format!("Failed to parse key: {}", e)))?;

        let params = CertificateParams::new(domains.to_vec())
            .map_err(|e| TlsError::Acme(format!("Failed to create cert params: {}", e)))?;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| TlsError::Acme(format!("Failed to generate placeholder cert: {}", e)))?;

        let cert_pem = cert.pem();

        let cert_path = cache_path.join("cert.pem");
        let key_path = cache_path.join("key.pem");

        std::fs::write(&cert_path, &cert_pem)?;
        std::fs::write(&key_path, key_pem)?;

        RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .map_err(|e| TlsError::CertificateLoad(e.to_string()))
    }

    /// Get the challenge state for the HTTP-01 server
    pub fn challenge_state(&self) -> AcmeChallengeState {
        self.challenge_state.clone()
    }

    /// Get the RustlsConfig for the HTTPS server
    pub fn rustls_config(&self) -> RustlsConfig {
        self.rustls_config.clone()
    }

    /// Provision or renew certificate
    pub async fn provision_certificate(&self) -> Result<(), TlsError> {
        info!(
            "Starting ACME certificate provisioning for {:?}",
            self.domains
        );

        // Create order
        let identifiers: Vec<_> = self
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to create order: {}", e)))?;

        // Process authorizations
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to get authorizations: {}", e)))?;

        for authz in authorizations {
            // Skip if already valid
            if authz.status == AuthorizationStatus::Valid {
                debug!("Authorization already valid, skipping");
                continue;
            }

            // Find HTTP-01 challenge
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| TlsError::Acme("No HTTP-01 challenge available".into()))?;

            // Set up challenge response
            let key_auth = order.key_authorization(challenge);
            {
                let mut challenges = self.challenge_state.challenges.write().await;
                challenges.insert(challenge.token.clone(), key_auth.as_str().to_string());
            }

            debug!(
                "Registered HTTP-01 challenge for token: {}",
                challenge.token
            );

            // Notify ACME server we're ready
            order
                .set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| TlsError::Acme(format!("Failed to set challenge ready: {}", e)))?;
        }

        // Poll for order completion
        let mut retries = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let state = order
                .refresh()
                .await
                .map_err(|e| TlsError::Acme(format!("Failed to refresh order: {}", e)))?;

            match state.status {
                OrderStatus::Ready => {
                    info!("ACME order ready, finalizing...");
                    break;
                }
                OrderStatus::Invalid => {
                    return Err(TlsError::Acme("Order became invalid".into()));
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    retries += 1;
                    if retries > 30 {
                        return Err(TlsError::Acme("Order timed out".into()));
                    }
                    debug!("Order status: {:?}, waiting...", state.status);
                }
                OrderStatus::Valid => {
                    info!("Order already valid");
                    // Certificate should be ready to download
                    return self.download_certificate(&mut order).await;
                }
            }
        }

        // Generate CSR and finalize
        let key_pair = KeyPair::from_pem(&self.key_pem)
            .map_err(|e| TlsError::Acme(format!("Failed to parse key: {}", e)))?;

        let params = CertificateParams::new(self.domains.clone())
            .map_err(|e| TlsError::Acme(format!("Failed to create CSR params: {}", e)))?;

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| TlsError::Acme(format!("Failed to serialize CSR: {}", e)))?;

        order
            .finalize(csr.der())
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to finalize order: {}", e)))?;

        // Wait for certificate to be ready
        let mut retries = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let state = order
                .refresh()
                .await
                .map_err(|e| TlsError::Acme(format!("Failed to refresh order: {}", e)))?;

            match state.status {
                OrderStatus::Valid => {
                    break;
                }
                OrderStatus::Invalid => {
                    return Err(TlsError::Acme(
                        "Order became invalid after finalization".into(),
                    ));
                }
                _ => {
                    retries += 1;
                    if retries > 30 {
                        return Err(TlsError::Acme("Timed out waiting for certificate".into()));
                    }
                }
            }
        }

        self.download_certificate(&mut order).await
    }

    async fn download_certificate(&self, order: &mut instant_acme::Order) -> Result<(), TlsError> {
        // Download certificate
        let cert_chain = order
            .certificate()
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to get certificate: {}", e)))?
            .ok_or_else(|| TlsError::Acme("No certificate returned".into()))?;

        // Save certificate and key
        let cert_path = self.cache_dir.join("cert.pem");
        let key_path = self.cache_dir.join("key.pem");

        std::fs::write(&cert_path, &cert_chain)?;
        std::fs::write(&key_path, &self.key_pem)?;

        // Reload the rustls config
        self.rustls_config
            .reload_from_pem_file(&cert_path, &key_path)
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to reload certificate: {}", e)))?;

        info!("ACME certificate provisioned and loaded successfully");

        // Clear challenges
        {
            let mut challenges = self.challenge_state.challenges.write().await;
            challenges.clear();
        }

        Ok(())
    }

    /// Start background renewal loop
    pub fn start_renewal_loop(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Initial provisioning
            if let Err(e) = self.provision_certificate().await {
                error!("Initial ACME provisioning failed: {}", e);
            }

            // Renewal loop - check daily
            let mut interval = tokio::time::interval(Duration::from_secs(86400));
            loop {
                interval.tick().await;

                // TODO: Check certificate expiry before renewal
                // For now, just log that we're checking
                debug!("Checking certificate renewal...");
            }
        })
    }
}

/// Build the HTTP-01 challenge server router
pub fn build_challenge_router(state: AcmeChallengeState) -> Router {
    Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(challenge_handler),
        )
        .with_state(state)
}

/// Handler for ACME HTTP-01 challenge requests
async fn challenge_handler(
    State(state): State<AcmeChallengeState>,
    AxumPath(token): AxumPath<String>,
) -> Result<String, axum::http::StatusCode> {
    let challenges = state.challenges.read().await;

    match challenges.get(&token) {
        Some(key_auth) => {
            debug!("Serving ACME challenge for token: {}", token);
            Ok(key_auth.clone())
        }
        None => {
            warn!("Unknown ACME challenge token requested: {}", token);
            Err(axum::http::StatusCode::NOT_FOUND)
        }
    }
}
