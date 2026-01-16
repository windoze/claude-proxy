//! TLS configuration and certificate management
//!
//! This module provides:
//! - Manual TLS setup from certificate files
//! - Integration with ACME-based automatic certificate provisioning

use axum_server::tls_rustls::RustlsConfig;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("Failed to load certificate: {0}")]
    CertificateLoad(String),

    #[error("Failed to load private key: {0}")]
    PrivateKeyLoad(String),

    #[error("ACME error: {0}")]
    Acme(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Create TLS configuration from manual cert/key files
pub async fn setup_manual_tls(cert_path: &str, key_path: &str) -> Result<RustlsConfig, TlsError> {
    // Verify files exist
    if !Path::new(cert_path).exists() {
        return Err(TlsError::CertificateLoad(format!(
            "Certificate file not found: {}",
            cert_path
        )));
    }
    if !Path::new(key_path).exists() {
        return Err(TlsError::PrivateKeyLoad(format!(
            "Key file not found: {}",
            key_path
        )));
    }

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| TlsError::CertificateLoad(e.to_string()))?;

    Ok(config)
}
