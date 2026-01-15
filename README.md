# Claude Proxy

A lightweight API proxy server for Claude and OpenAI APIs, written in Rust using Axum. It handles authentication translation and request forwarding between clients and upstream API providers.

## Features

- Proxy requests to Claude API, OpenAI API, or Microsoft AI Foundry
- Multiple upstream authentication methods:
  - Direct API key passthrough
  - Azure AD (Entra ID) with client credentials
  - Azure CLI credentials for local development
- Client API key validation with passthrough mode for unauthenticated requests
- Streaming (SSE) response support
- Configurable logging with file rotation

## Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))

## Building

```bash
# Build the project
cargo build --release

# The binary will be at target/release/claude-proxy
```

## Configuration

A configuration file is required. The proxy searches for config files in this order:

1. Path specified via `--config` CLI flag
2. `CLAUDE_PROXY_CONFIG_FILE` environment variable
3. `config.toml` in the current directory
4. `~/.config/claude-proxy/config.toml` (Linux/macOS)
5. `~/.claude-proxy.toml`

### Quick Start

Copy the example configuration and customize it:

```bash
cp config.example.toml config.toml
```

### Basic Configuration

```toml
# Server settings
bind_address = "0.0.0.0"
port = 8080

# Upstream API URL
upstream_url = "https://api.anthropic.com"

# API key that clients must provide to access this proxy
client_api_key = "your-client-api-key"

# Upstream authentication (API key)
[upstream_auth]
type = "api_key"
api_key = "your-upstream-api-key"
```

### Environment Variable Expansion

Config values support environment variable expansion using `${VAR}` or `$VAR` syntax:

```toml
client_api_key = "${DOWNSTREAM_API_KEY}"

[upstream_auth]
type = "api_key"
api_key = "${UPSTREAM_API_KEY}"
```

### Upstream Authentication Options

**Option 1: API Key** (Claude/OpenAI)
```toml
[upstream_auth]
type = "api_key"
api_key = "sk-..."
```

**Option 2: Azure AD** (Microsoft AI Foundry only)
```toml
[upstream_auth]
type = "azure_ad"
tenant_id = "${AZURE_TENANT_ID}"
client_id = "${AZURE_CLIENT_ID}"
client_secret = "${AZURE_CLIENT_SECRET}"
scope = "https://ai.azure.com/.default"
```

**Option 3: Azure CLI** (Microsoft AI Foundry only)
```toml
[upstream_auth]
type = "azure_cli"
scope = "https://ai.azure.com/.default"
```

### Logging Configuration

```toml
[logging]
log_path = "/var/log/claude-proxy"  # Optional: omit for stdout only
rotation = "daily"                   # "hourly" or "daily"
level = "info"                       # trace, debug, info, warn, error
log_prefix = "claude-proxy"
```

## Running

```bash
# Run with default config file discovery
cargo run --release

# Run with a specific config file
cargo run --release -- --config /path/to/config.toml

# Run with verbose logging (debug level)
cargo run --release -- --verbose
```

## Usage

Once running, point your Claude/OpenAI clients to the proxy:

```bash
# Example: Using curl with the Claude API
curl http://localhost:8080/v1/messages \
  -H "x-api-key: your-client-api-key" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

The proxy also accepts the `Authorization: Bearer` header format for client authentication.

## License

MIT
