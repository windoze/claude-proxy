mod auth;
mod config;
mod middleware;
mod proxy;

use axum::{middleware as axum_middleware, routing::any, Router};
use clap::Parser;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::auth::create_upstream_auth;
use crate::config::{LogLevel, LogRotation, ProxyConfig};
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

    // Load configuration first (needed for logging setup)
    let config = load_config_without_logging(args.config.clone())?;

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

/// Load configuration without logging (used before logging is initialized)
fn load_config_without_logging(
    cli_config_path: Option<String>,
) -> Result<ProxyConfig, Box<dyn std::error::Error>> {
    // Priority: CLI argument > environment variable > default paths
    if let Some(ref path) = cli_config_path {
        if std::path::Path::new(path).exists() {
            return Ok(ProxyConfig::from_file(path)?);
        } else {
            return Err(format!("Configuration file not found: {}", path).into());
        }
    }

    if let Ok(env_path) = std::env::var("CLAUDE_PROXY_CONFIG_FILE") {
        if std::path::Path::new(&env_path).exists() {
            return Ok(ProxyConfig::from_file(&env_path)?);
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
            return Ok(ProxyConfig::from_file(path)?);
        }
    }

    // No config file found - provide helpful error message
    Err(format!(
        "No configuration file found. Please create a config file at one of:\n  \
         - ./config.toml\n  \
         - {}\n  \
         - {}\n\
         Or specify a config file with --config <path> or CLAUDE_PROXY_CONFIG_FILE environment variable.",
        default_paths.get(1).map(|s| s.as_str()).unwrap_or("~/.config/claude-proxy/config.toml"),
        default_paths.get(2).map(|s| s.as_str()).unwrap_or("~/.claude-proxy.toml")
    )
    .into())
}
