mod auth;
mod config;
mod middleware;
mod proxy;

use axum::{middleware as axum_middleware, routing::any, Router};
use clap::Parser;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::auth::create_upstream_auth;
use crate::config::ProxyConfig;
use crate::middleware::{validate_client_api_key, ApiKeyValidatorState};
use crate::proxy::{proxy_handler, ProxyState};

/// Claude API Proxy - A proxy server for the Claude API with multiple authentication backends
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Enable verbose (debug) logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments first (before logging init)
    let args = Args::parse();

    // Initialize logging with appropriate level
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load configuration
    let config = load_config(args.config)?;

    info!("Starting Claude API Proxy");
    info!("Listening on {}:{}", config.bind_address, config.port);
    info!("Upstream URL: {}", config.upstream_url);

    // Create upstream auth provider
    let upstream_auth = create_upstream_auth(&config.upstream_auth);

    // Create HTTP client for upstream requests
    let http_client = reqwest::Client::builder().build()?;

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
    let app = Router::new()
        .route("/{*path}", any(proxy_handler))
        .route("/", any(proxy_handler))
        .layer(axum_middleware::from_fn_with_state(
            api_key_state,
            validate_client_api_key,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(proxy_state);

    // Start the server
    let addr: SocketAddr = format!("{}:{}", config.bind_address, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("Claude API Proxy is ready to accept connections");

    axum::serve(listener, app).await?;

    Ok(())
}

fn load_config(cli_config_path: Option<String>) -> Result<ProxyConfig, Box<dyn std::error::Error>> {
    // Priority: CLI argument > environment variable > default path
    let explicit_path = cli_config_path.is_some();
    let config_path = cli_config_path
        .or_else(|| std::env::var("CLAUDE_PROXY_CONFIG_FILE").ok())
        .unwrap_or_else(|| "config.toml".to_string());

    if std::path::Path::new(&config_path).exists() {
        info!("Loading configuration from {}", config_path);
        Ok(ProxyConfig::from_file(&config_path)?)
    } else if explicit_path {
        // If a config file was explicitly specified but doesn't exist, return an error
        Err(format!("Configuration file not found: {}", config_path).into())
    } else {
        info!("Loading configuration from environment variables");
        Ok(ProxyConfig::from_env()?)
    }
}
