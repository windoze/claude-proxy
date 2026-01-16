mod acme;
mod auth;
mod config;
mod middleware;
mod proxy;
mod tls;

use axum::{middleware as axum_middleware, routing::any, Router};
use clap::Parser;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::auth::create_upstream_auth;
use crate::config::{
    LogLevel, LogRotation, LoggingConfig, ProxyConfig, TlsConfig, UpstreamAuthConfig,
};
use crate::middleware::{validate_client_api_key, ApiKeyValidatorState};
use crate::proxy::{proxy_handler, ProxyState};

/// Claude API Proxy - A proxy server for the Claude API with multiple authentication backends
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file (optional if required params are set via CLI/env)
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Enable verbose (debug) logging
    #[arg(short, long)]
    verbose: bool,

    // Server settings
    /// Address to bind the proxy server to
    #[arg(long, value_name = "ADDRESS")]
    bind_address: Option<String>,

    /// Port to listen on
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,

    /// Upstream API URL
    #[arg(long, value_name = "URL")]
    upstream_url: Option<String>,

    /// API key that clients must provide to access this proxy
    #[arg(long, value_name = "KEY")]
    client_api_key: Option<String>,

    // Upstream auth settings
    /// Upstream authentication type: api_key, azure_ad, azure_cli, azure_managed_identity
    #[arg(long, value_name = "TYPE")]
    upstream_auth_type: Option<String>,

    /// API key for upstream authentication (when type=api_key)
    #[arg(long, value_name = "KEY")]
    upstream_api_key: Option<String>,

    /// Azure AD tenant ID (when type=azure_ad)
    #[arg(long, value_name = "ID")]
    azure_tenant_id: Option<String>,

    /// Azure AD client ID (when type=azure_ad or azure_managed_identity)
    #[arg(long, value_name = "ID")]
    azure_client_id: Option<String>,

    /// Azure AD client secret (when type=azure_ad)
    #[arg(long, value_name = "SECRET")]
    azure_client_secret: Option<String>,

    /// Azure scope/resource (when type=azure_ad, azure_cli, or azure_managed_identity)
    #[arg(long, value_name = "SCOPE")]
    azure_scope: Option<String>,

    // Logging settings
    /// Path to log file directory
    #[arg(long, value_name = "PATH")]
    log_path: Option<String>,

    /// Log rotation: hourly or daily
    #[arg(long, value_name = "ROTATION")]
    log_rotation: Option<String>,

    /// Log level: trace, debug, info, warn, error
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Prefix for log file names
    #[arg(long, value_name = "PREFIX")]
    log_prefix: Option<String>,

    // TLS settings
    /// TLS mode: disabled, manual, or acme
    #[arg(long, value_name = "MODE")]
    tls_mode: Option<String>,

    /// Path to TLS certificate file (manual mode)
    #[arg(long, value_name = "PATH")]
    tls_cert_path: Option<String>,

    /// Path to TLS private key file (manual mode)
    #[arg(long, value_name = "PATH")]
    tls_key_path: Option<String>,

    /// HTTPS listen port (default: 443)
    #[arg(long, value_name = "PORT")]
    https_port: Option<u16>,

    /// ACME contact email
    #[arg(long, value_name = "EMAIL")]
    acme_email: Option<String>,

    /// ACME domains (comma-separated)
    #[arg(long, value_name = "DOMAINS")]
    acme_domains: Option<String>,

    /// ACME directory URL (default: Let's Encrypt production)
    #[arg(long, value_name = "URL")]
    acme_directory_url: Option<String>,

    /// ACME cache directory for certificates and account
    #[arg(long, value_name = "PATH")]
    acme_cache_dir: Option<String>,

    /// HTTP port for ACME HTTP-01 challenges (default: 80)
    #[arg(long, value_name = "PORT")]
    http_challenge_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments first (before logging init)
    let args = Args::parse();

    // Load configuration first (needed for logging setup)
    let config = load_config_without_logging(&args)?;

    // Initialize logging with appropriate level
    // --verbose flag overrides config setting to DEBUG
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        match config.logging.level {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    };

    // Set up logging based on configuration
    let _guard = init_logging(log_level, &config)?;

    info!("Starting Claude API Proxy");
    info!("Upstream URL: {}", config.upstream_url);

    // Build the main proxy router
    let app = build_proxy_router(&config);

    // Start server(s) based on TLS configuration
    match &config.tls {
        TlsConfig::Disabled => {
            info!(
                "TLS disabled, starting HTTP server on {}:{}",
                config.bind_address, config.port
            );
            start_http_server(app, &config).await?;
        }
        TlsConfig::Manual {
            cert_path,
            key_path,
            https_port,
        } => {
            info!(
                "TLS enabled (manual mode), starting HTTPS server on {}:{}",
                config.bind_address, https_port
            );
            start_https_server_manual(app, &config, cert_path, key_path, *https_port).await?;
        }
        TlsConfig::Acme {
            email,
            domains,
            directory_url,
            cache_dir,
            https_port,
            http_challenge_port,
        } => {
            info!("TLS enabled (ACME mode) for domains: {:?}", domains);
            info!(
                "HTTPS server on {}:{}, HTTP challenge server on {}:{}",
                config.bind_address, https_port, config.bind_address, http_challenge_port
            );
            start_https_server_acme(
                app,
                &config,
                email,
                domains,
                directory_url,
                cache_dir,
                *https_port,
                *http_challenge_port,
            )
            .await?;
        }
    }

    Ok(())
}

/// Build the main proxy router
fn build_proxy_router(config: &ProxyConfig) -> Router {
    // Create upstream auth provider
    let upstream_auth = create_upstream_auth(&config.upstream_auth);

    // Create HTTP client for upstream requests
    let http_client = reqwest::Client::builder()
        .build()
        .expect("Failed to create HTTP client");

    // Create proxy state
    let proxy_state = ProxyState {
        upstream_url: config.upstream_url.clone(),
        upstream_auth,
        http_client,
    };

    // Create API key validator state
    let api_key_state = ApiKeyValidatorState {
        expected_api_key: config.client_api_key.clone(),
    };

    // Build the router
    Router::new()
        .route("/{*path}", any(proxy_handler))
        .route("/", any(proxy_handler))
        .layer(axum_middleware::from_fn_with_state(
            api_key_state,
            validate_client_api_key,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(proxy_state)
}

/// Start plain HTTP server (existing behavior when TLS is disabled)
async fn start_http_server(
    app: Router,
    config: &ProxyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = format!("{}:{}", config.bind_address, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!(
        "Claude API Proxy is ready to accept connections on http://{}",
        addr
    );
    axum::serve(listener, app).await?;

    Ok(())
}

/// Start HTTPS server with manual certificate files
async fn start_https_server_manual(
    app: Router,
    config: &ProxyConfig,
    cert_path: &str,
    key_path: &str,
    https_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let rustls_config = tls::setup_manual_tls(cert_path, key_path).await?;
    let addr: SocketAddr = format!("{}:{}", config.bind_address, https_port).parse()?;

    info!(
        "Claude API Proxy is ready to accept connections on https://{}",
        addr
    );

    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

/// Start HTTPS server with ACME certificate provisioning
/// Also starts a separate HTTP server for ACME HTTP-01 challenges
#[allow(clippy::too_many_arguments)]
async fn start_https_server_acme(
    app: Router,
    config: &ProxyConfig,
    email: &str,
    domains: &[String],
    directory_url: &str,
    cache_dir: &str,
    https_port: u16,
    http_challenge_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    // Create ACME manager
    let manager =
        Arc::new(acme::AcmeManager::new(email, domains.to_vec(), directory_url, cache_dir).await?);

    let rustls_config = manager.rustls_config();
    let challenge_state = manager.challenge_state();

    // Start certificate renewal background task
    let _renewal_handle = manager.clone().start_renewal_loop();

    // Build HTTP-01 challenge server
    let challenge_app = acme::build_challenge_router(challenge_state);
    let challenge_addr: SocketAddr =
        format!("{}:{}", config.bind_address, http_challenge_port).parse()?;

    // Build HTTPS server address
    let https_addr: SocketAddr = format!("{}:{}", config.bind_address, https_port).parse()?;

    info!(
        "Starting ACME HTTP-01 challenge server on http://{}",
        challenge_addr
    );
    info!(
        "Claude API Proxy is ready to accept connections on https://{}",
        https_addr
    );

    // Run both servers concurrently
    tokio::select! {
        result = start_challenge_server(challenge_app, challenge_addr) => {
            result?;
        }
        result = start_tls_server(app, https_addr, rustls_config) => {
            result?;
        }
    }

    Ok(())
}

/// Start the HTTP-01 challenge server
async fn start_challenge_server(
    app: Router,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Start the TLS server
async fn start_tls_server(
    app: Router,
    addr: SocketAddr,
    config: axum_server::tls_rustls::RustlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

/// Initialize logging with optional file rotation.
/// Returns a guard that must be kept alive for the duration of the program
/// to ensure logs are flushed properly.
fn init_logging(
    log_level: Level,
    config: &ProxyConfig,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>, Box<dyn std::error::Error>> {
    match &config.logging.log_path {
        Some(log_path) => {
            // Create the log directory if it doesn't exist
            std::fs::create_dir_all(log_path)?;

            // Determine rotation frequency
            let rotation = match config.logging.rotation {
                LogRotation::Hourly => Rotation::HOURLY,
                LogRotation::Daily => Rotation::DAILY,
            };

            // Create rolling file appender
            let file_appender =
                RollingFileAppender::new(rotation, log_path, &config.logging.log_prefix);

            // Create non-blocking writer
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            // Set up subscriber with both stdout and file output
            tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .with_target(false)
                        .with_writer(std::io::stdout)
                        .with_filter(tracing_subscriber::filter::LevelFilter::from_level(
                            log_level,
                        )),
                )
                .with(
                    fmt::layer()
                        .with_target(false)
                        .with_ansi(false)
                        .with_writer(non_blocking)
                        .with_filter(tracing_subscriber::filter::LevelFilter::from_level(
                            log_level,
                        )),
                )
                .init();

            Ok(Some(guard))
        }
        None => {
            // No log path specified, only log to stdout
            tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .with_target(false)
                        .with_writer(std::io::stdout)
                        .with_filter(tracing_subscriber::filter::LevelFilter::from_level(
                            log_level,
                        )),
                )
                .init();

            Ok(None)
        }
    }
}

/// Load configuration with layered precedence: CLI > env > file > defaults
fn load_config_without_logging(args: &Args) -> Result<ProxyConfig, Box<dyn std::error::Error>> {
    // First, try to load from config file (if available)
    let file_config = load_config_file(args.config.as_deref())?;

    // Build the final config by merging layers
    let config = build_config(args, file_config)?;

    Ok(config)
}

/// Try to load config from file, returns None if no file is found/specified
fn load_config_file(
    cli_config_path: Option<&str>,
) -> Result<Option<ProxyConfig>, Box<dyn std::error::Error>> {
    // Priority: CLI argument > environment variable > default paths
    if let Some(path) = cli_config_path {
        if std::path::Path::new(path).exists() {
            return Ok(Some(ProxyConfig::from_file(path)?));
        } else {
            return Err(format!("Configuration file not found: {}", path).into());
        }
    }

    if let Ok(env_path) = std::env::var("CLAUDE_PROXY_CONFIG_FILE") {
        if std::path::Path::new(&env_path).exists() {
            return Ok(Some(ProxyConfig::from_file(&env_path)?));
        } else {
            return Err(format!(
                "Configuration file specified in CLAUDE_PROXY_CONFIG_FILE not found: {}",
                env_path
            )
            .into());
        }
    }

    // Check default paths in order of priority
    let default_paths: Vec<String> = [
        Some("config.toml".to_string()),
        dirs::config_dir()
            .map(|p| p.join("claude-proxy").join("config.toml"))
            .and_then(|p| p.to_str().map(String::from)),
        dirs::home_dir()
            .map(|p| p.join(".claude-proxy.toml"))
            .and_then(|p| p.to_str().map(String::from)),
    ]
    .into_iter()
    .flatten()
    .collect();

    for path in &default_paths {
        if std::path::Path::new(path).exists() {
            return Ok(Some(ProxyConfig::from_file(path)?));
        }
    }

    // No config file found - this is OK, we can build from CLI/env
    Ok(None)
}

/// Get value with precedence: CLI > env > file > default
fn get_value<T: Clone + 'static>(cli: Option<T>, env_var: &str, file: Option<T>, default: T) -> T {
    if let Some(v) = cli {
        return v;
    }
    if let Ok(v) = std::env::var(env_var) {
        if let Some(parsed) = parse_env_value::<T>(&v) {
            return parsed;
        }
    }
    file.unwrap_or(default)
}

/// Get optional value with precedence: CLI > env > file
fn get_optional_value<T: Clone + 'static>(
    cli: Option<T>,
    env_var: &str,
    file: Option<T>,
) -> Option<T> {
    if cli.is_some() {
        return cli;
    }
    if let Ok(v) = std::env::var(env_var) {
        if let Some(parsed) = parse_env_value::<T>(&v) {
            return Some(parsed);
        }
    }
    file
}

/// Parse environment variable value to target type
fn parse_env_value<T: 'static>(value: &str) -> Option<T> {
    use std::any::TypeId;

    // This is a bit hacky but works for our use case
    if TypeId::of::<T>() == TypeId::of::<String>() {
        // SAFETY: We just checked T is String
        Some(unsafe { std::mem::transmute_copy(&value.to_string()) })
    } else if TypeId::of::<T>() == TypeId::of::<u16>() {
        value.parse::<u16>().ok().map(|v| {
            // SAFETY: We just checked T is u16
            unsafe { std::mem::transmute_copy(&v) }
        })
    } else {
        None
    }
}

/// Build the final config by merging CLI args, env vars, file config, and defaults
fn build_config(
    args: &Args,
    file_config: Option<ProxyConfig>,
) -> Result<ProxyConfig, Box<dyn std::error::Error>> {
    let default_azure_scope = "https://ai.azure.com/.default".to_string();

    // Extract file values
    let (file_bind_address, file_port, file_upstream_url, file_client_api_key, file_upstream_auth) =
        if let Some(ref fc) = file_config {
            (
                Some(fc.bind_address.clone()),
                Some(fc.port),
                Some(fc.upstream_url.clone()),
                Some(fc.client_api_key.clone()),
                Some(fc.upstream_auth.clone()),
            )
        } else {
            (None, None, None, None, None)
        };

    let file_logging = file_config.as_ref().map(|fc| fc.logging.clone());

    // Build basic config values
    let bind_address = get_value(
        args.bind_address.clone(),
        "CLAUDE_PROXY__BIND_ADDRESS",
        file_bind_address,
        "0.0.0.0".to_string(),
    );

    let port = get_value(args.port, "CLAUDE_PROXY__PORT", file_port, 8080);

    let upstream_url = get_optional_value(
        args.upstream_url.clone(),
        "CLAUDE_PROXY__UPSTREAM_URL",
        file_upstream_url,
    );

    let client_api_key = get_optional_value(
        args.client_api_key.clone(),
        "CLAUDE_PROXY__CLIENT_API_KEY",
        file_client_api_key,
    );

    // Build upstream auth config
    let upstream_auth = build_upstream_auth(args, file_upstream_auth, &default_azure_scope)?;

    // Build logging config
    let logging = build_logging_config(args, file_logging);

    // Validate required fields
    let upstream_url = upstream_url.ok_or(
        "upstream_url is required. Set via --upstream-url, CLAUDE_PROXY__UPSTREAM_URL, or config file."
    )?;

    let client_api_key = client_api_key.ok_or(
        "client_api_key is required. Set via --client-api-key, CLAUDE_PROXY__CLIENT_API_KEY, or config file."
    )?;

    // Build TLS config
    let file_tls = file_config.as_ref().map(|fc| fc.tls.clone());
    let tls = build_tls_config(args, file_tls)?;

    Ok(ProxyConfig {
        bind_address,
        port,
        upstream_url,
        client_api_key,
        upstream_auth,
        logging,
        tls,
    })
}

/// Build upstream auth config from CLI args, env vars, and file config
fn build_upstream_auth(
    args: &Args,
    file_auth: Option<UpstreamAuthConfig>,
    default_azure_scope: &str,
) -> Result<UpstreamAuthConfig, Box<dyn std::error::Error>> {
    // Determine auth type: CLI > env > file
    let auth_type = args
        .upstream_auth_type
        .clone()
        .or_else(|| std::env::var("CLAUDE_PROXY__UPSTREAM_AUTH__TYPE").ok())
        .or_else(|| file_auth.as_ref().map(|a| auth_type_name(a).to_string()));

    let auth_type = auth_type.ok_or(
        "upstream_auth.type is required. Set via --upstream-auth-type, CLAUDE_PROXY__UPSTREAM_AUTH__TYPE, or config file."
    )?;

    match auth_type.as_str() {
        "api_key" => {
            let api_key = get_optional_value(
                args.upstream_api_key.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__API_KEY",
                match &file_auth {
                    Some(UpstreamAuthConfig::ApiKey { api_key }) => Some(api_key.clone()),
                    _ => None,
                },
            )
            .ok_or("upstream_auth.api_key is required for api_key auth type. Set via --upstream-api-key, CLAUDE_PROXY__UPSTREAM_AUTH__API_KEY, or config file.")?;

            Ok(UpstreamAuthConfig::ApiKey { api_key })
        }
        "azure_ad" => {
            let tenant_id = get_optional_value(
                args.azure_tenant_id.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__TENANT_ID",
                match &file_auth {
                    Some(UpstreamAuthConfig::AzureAd { tenant_id, .. }) => Some(tenant_id.clone()),
                    _ => None,
                },
            )
            .ok_or("upstream_auth.tenant_id is required for azure_ad auth type. Set via --azure-tenant-id, CLAUDE_PROXY__UPSTREAM_AUTH__TENANT_ID, or config file.")?;

            let client_id = get_optional_value(
                args.azure_client_id.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_ID",
                match &file_auth {
                    Some(UpstreamAuthConfig::AzureAd { client_id, .. }) => Some(client_id.clone()),
                    _ => None,
                },
            )
            .ok_or("upstream_auth.client_id is required for azure_ad auth type. Set via --azure-client-id, CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_ID, or config file.")?;

            let client_secret = get_optional_value(
                args.azure_client_secret.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_SECRET",
                match &file_auth {
                    Some(UpstreamAuthConfig::AzureAd { client_secret, .. }) => {
                        Some(client_secret.clone())
                    }
                    _ => None,
                },
            )
            .ok_or("upstream_auth.client_secret is required for azure_ad auth type. Set via --azure-client-secret, CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_SECRET, or config file.")?;

            let scope = get_value(
                args.azure_scope.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__SCOPE",
                match &file_auth {
                    Some(UpstreamAuthConfig::AzureAd { scope, .. }) => Some(scope.clone()),
                    _ => None,
                },
                default_azure_scope.to_string(),
            );

            Ok(UpstreamAuthConfig::AzureAd {
                tenant_id,
                client_id,
                client_secret,
                scope,
            })
        }
        "azure_cli" => {
            let scope = get_value(
                args.azure_scope.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__SCOPE",
                match &file_auth {
                    Some(UpstreamAuthConfig::AzureCli { scope }) => Some(scope.clone()),
                    _ => None,
                },
                default_azure_scope.to_string(),
            );

            Ok(UpstreamAuthConfig::AzureCli { scope })
        }
        "azure_managed_identity" => {
            let client_id = get_optional_value(
                args.azure_client_id.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_ID",
                match &file_auth {
                    Some(UpstreamAuthConfig::AzureManagedIdentity { client_id, .. }) => {
                        client_id.clone()
                    }
                    _ => None,
                },
            );

            let resource = get_value(
                args.azure_scope.clone(),
                "CLAUDE_PROXY__UPSTREAM_AUTH__RESOURCE",
                match &file_auth {
                    Some(UpstreamAuthConfig::AzureManagedIdentity { resource, .. }) => {
                        Some(resource.clone())
                    }
                    _ => None,
                },
                default_azure_scope.to_string(),
            );

            Ok(UpstreamAuthConfig::AzureManagedIdentity { client_id, resource })
        }
        _ => Err(format!(
            "Unknown upstream_auth.type: '{}'. Valid types: api_key, azure_ad, azure_cli, azure_managed_identity",
            auth_type
        )
        .into()),
    }
}

/// Get the type name for an UpstreamAuthConfig variant
fn auth_type_name(auth: &UpstreamAuthConfig) -> &'static str {
    match auth {
        UpstreamAuthConfig::ApiKey { .. } => "api_key",
        UpstreamAuthConfig::AzureAd { .. } => "azure_ad",
        UpstreamAuthConfig::AzureCli { .. } => "azure_cli",
        UpstreamAuthConfig::AzureManagedIdentity { .. } => "azure_managed_identity",
    }
}

/// Build logging config from CLI args, env vars, and file config
fn build_logging_config(args: &Args, file_logging: Option<LoggingConfig>) -> LoggingConfig {
    let file_log_path = file_logging.as_ref().and_then(|l| l.log_path.clone());
    let file_rotation = file_logging.as_ref().map(|l| l.rotation);
    let file_level = file_logging.as_ref().map(|l| l.level);
    let file_prefix = file_logging.as_ref().map(|l| l.log_prefix.clone());

    let log_path = get_optional_value(
        args.log_path.clone(),
        "CLAUDE_PROXY__LOGGING__LOG_PATH",
        file_log_path,
    );

    let rotation = args
        .log_rotation
        .as_ref()
        .and_then(|r| parse_log_rotation(r))
        .or_else(|| {
            std::env::var("CLAUDE_PROXY__LOGGING__ROTATION")
                .ok()
                .and_then(|r| parse_log_rotation(&r))
        })
        .or(file_rotation)
        .unwrap_or_default();

    let level = args
        .log_level
        .as_ref()
        .and_then(|l| parse_log_level(l))
        .or_else(|| {
            std::env::var("CLAUDE_PROXY__LOGGING__LEVEL")
                .ok()
                .and_then(|l| parse_log_level(&l))
        })
        .or(file_level)
        .unwrap_or_default();

    let log_prefix = get_value(
        args.log_prefix.clone(),
        "CLAUDE_PROXY__LOGGING__LOG_PREFIX",
        file_prefix,
        "claude-proxy".to_string(),
    );

    LoggingConfig {
        log_path,
        rotation,
        level,
        log_prefix,
    }
}

fn parse_log_rotation(s: &str) -> Option<LogRotation> {
    match s.to_lowercase().as_str() {
        "hourly" => Some(LogRotation::Hourly),
        "daily" => Some(LogRotation::Daily),
        _ => None,
    }
}

fn parse_log_level(s: &str) -> Option<LogLevel> {
    match s.to_lowercase().as_str() {
        "trace" => Some(LogLevel::Trace),
        "debug" => Some(LogLevel::Debug),
        "info" => Some(LogLevel::Info),
        "warn" => Some(LogLevel::Warn),
        "error" => Some(LogLevel::Error),
        _ => None,
    }
}

/// Build TLS config from CLI args, env vars, and file config
fn build_tls_config(
    args: &Args,
    file_tls: Option<TlsConfig>,
) -> Result<TlsConfig, Box<dyn std::error::Error>> {
    // Determine TLS mode: CLI > env > file > default (disabled)
    let tls_mode = args
        .tls_mode
        .clone()
        .or_else(|| std::env::var("CLAUDE_PROXY__TLS__MODE").ok())
        .or_else(|| file_tls.as_ref().map(|t| tls_mode_name(t).to_string()))
        .unwrap_or_else(|| "disabled".to_string());

    match tls_mode.to_lowercase().as_str() {
        "disabled" => Ok(TlsConfig::Disabled),
        "manual" => {
            let cert_path = get_optional_value(
                args.tls_cert_path.clone(),
                "CLAUDE_PROXY__TLS__CERT_PATH",
                match &file_tls {
                    Some(TlsConfig::Manual { cert_path, .. }) => Some(cert_path.clone()),
                    _ => None,
                },
            )
            .ok_or("tls.cert_path is required for manual TLS mode. Set via --tls-cert-path, CLAUDE_PROXY__TLS__CERT_PATH, or config file.")?;

            let key_path = get_optional_value(
                args.tls_key_path.clone(),
                "CLAUDE_PROXY__TLS__KEY_PATH",
                match &file_tls {
                    Some(TlsConfig::Manual { key_path, .. }) => Some(key_path.clone()),
                    _ => None,
                },
            )
            .ok_or("tls.key_path is required for manual TLS mode. Set via --tls-key-path, CLAUDE_PROXY__TLS__KEY_PATH, or config file.")?;

            let https_port = get_value(
                args.https_port,
                "CLAUDE_PROXY__TLS__HTTPS_PORT",
                match &file_tls {
                    Some(TlsConfig::Manual { https_port, .. }) => Some(*https_port),
                    _ => None,
                },
                443,
            );

            Ok(TlsConfig::Manual {
                cert_path,
                key_path,
                https_port,
            })
        }
        "acme" => {
            let email = get_optional_value(
                args.acme_email.clone(),
                "CLAUDE_PROXY__TLS__EMAIL",
                match &file_tls {
                    Some(TlsConfig::Acme { email, .. }) => Some(email.clone()),
                    _ => None,
                },
            )
            .ok_or("tls.email is required for ACME mode. Set via --acme-email, CLAUDE_PROXY__TLS__EMAIL, or config file.")?;

            // Parse domains from CLI (comma-separated) or use file/env
            let domains = if let Some(domains_str) = args.acme_domains.clone() {
                domains_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
            } else if let Ok(domains_str) = std::env::var("CLAUDE_PROXY__TLS__DOMAINS") {
                domains_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
            } else {
                match &file_tls {
                    Some(TlsConfig::Acme { domains, .. }) => domains.clone(),
                    _ => Vec::new(),
                }
            };

            if domains.is_empty() {
                return Err("tls.domains is required for ACME mode. Set via --acme-domains, CLAUDE_PROXY__TLS__DOMAINS, or config file.".into());
            }

            let directory_url = get_value(
                args.acme_directory_url.clone(),
                "CLAUDE_PROXY__TLS__DIRECTORY_URL",
                match &file_tls {
                    Some(TlsConfig::Acme { directory_url, .. }) => Some(directory_url.clone()),
                    _ => None,
                },
                "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            );

            let cache_dir = get_value(
                args.acme_cache_dir.clone(),
                "CLAUDE_PROXY__TLS__CACHE_DIR",
                match &file_tls {
                    Some(TlsConfig::Acme { cache_dir, .. }) => Some(cache_dir.clone()),
                    _ => None,
                },
                dirs::data_local_dir()
                    .map(|p| p.join("claude-proxy").join("acme"))
                    .and_then(|p| p.to_str().map(String::from))
                    .unwrap_or_else(|| "/var/lib/claude-proxy/acme".to_string()),
            );

            let https_port = get_value(
                args.https_port,
                "CLAUDE_PROXY__TLS__HTTPS_PORT",
                match &file_tls {
                    Some(TlsConfig::Acme { https_port, .. }) => Some(*https_port),
                    _ => None,
                },
                443,
            );

            let http_challenge_port = get_value(
                args.http_challenge_port,
                "CLAUDE_PROXY__TLS__HTTP_CHALLENGE_PORT",
                match &file_tls {
                    Some(TlsConfig::Acme {
                        http_challenge_port,
                        ..
                    }) => Some(*http_challenge_port),
                    _ => None,
                },
                80,
            );

            Ok(TlsConfig::Acme {
                email,
                domains,
                directory_url,
                cache_dir,
                https_port,
                http_challenge_port,
            })
        }
        _ => Err(format!(
            "Unknown TLS mode: '{}'. Valid modes: disabled, manual, acme",
            tls_mode
        )
        .into()),
    }
}

/// Get the mode name for a TlsConfig variant
fn tls_mode_name(tls: &TlsConfig) -> &'static str {
    match tls {
        TlsConfig::Disabled => "disabled",
        TlsConfig::Manual { .. } => "manual",
        TlsConfig::Acme { .. } => "acme",
    }
}
