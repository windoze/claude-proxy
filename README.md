# Claude Proxy

The main purpose of this proxy is to enable using Claude and OpenAI compatible clients with Microsoft AI Foundry, which may use AAD auth and most clients do not support it natively.

The proxy does byte-to-byte forwarding of requests and responses, with the exception of base URL and authentication headers. So it should work with any client that supports Claude or OpenAI APIs, including streaming responses and other extended features.

## Features

- Proxy requests to Claude API, OpenAI API, or any model that Microsoft AI Foundry supports
- Multiple upstream authentication methods:
  - Direct API key passthrough
  - Azure AD (Entra ID) with client credentials
  - Azure CLI credentials for local development
  - Azure Managed Identity for Azure-hosted workloads
- Client API key validation with passthrough mode for unauthenticated requests
- Streaming (SSE) response support
- Configurable logging with file rotation
- TLS/HTTPS support with manual certificates or automatic ACME (Let's Encrypt)

## Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))

## Building

```bash
# Build the project
cargo build --release

# The binary will be at target/release/claude-proxy
```

## Configuration

Configuration can be provided via a TOML file, CLI flags, or environment variables (or a combination). The proxy searches for config files in this order:

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

**Option 4: Azure Managed Identity** (Microsoft AI Foundry only)
```toml
[upstream_auth]
type = "azure_managed_identity"
# Optional: client_id for user-assigned managed identity
# client_id = "your-user-assigned-identity-client-id"
resource = "https://ai.azure.com/.default"
```

### Configure Claude Code and OpenAI Codex

In `~/.claude/settings.json`, set the API base URL to point to your proxy:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://<proxy-ip:port>/anthropic",
    "ANTHROPIC_AUTH_TOKEN": "blah-blah-blah"
  },
  // ...
}
```

In `~/.codex/config.toml`, set the OpenAI API base URL:

```toml
base_url = "http://<proxy-ip:port>/openai"
```

When using Microsoft AI Foundry, ensure your have trailing `/anthropic` or `/openai` in the base URL, the proxy simply appends the URL path to the base URL.
When using Claude official API or OpenAI official API, the base URL can be simply `http://<proxy-ip:port>`, the trailing part should **not** be included.

### Configure other API clients

When using Microsoft AI Foundry, make sure to set the API base URL to include `/anthropic` or `/openai` path accordingly, Microsoft uses different endpoints for models provided by different vendors, without correct path the requests will fail.

For example, an OpenAI client should set the base URL to `http://<proxy-ip:port>/openai`.

### Logging Configuration

```toml
[logging]
log_path = "/var/log/claude-proxy"  # Optional: omit for stdout only
rotation = "daily"                   # "hourly" or "daily"
level = "info"                       # trace, debug, info, warn, error
log_prefix = "claude-proxy"
```

### TLS Configuration

The proxy supports TLS/HTTPS with two modes: manual certificates or automatic provisioning via ACME (Let's Encrypt).

**Option 1: Disabled (default)**

If the `[tls]` section is omitted, the proxy runs in HTTP-only mode.

**Option 2: Manual TLS**

Provide your own certificate and key files:

```toml
[tls]
mode = "manual"
cert_path = "/etc/ssl/certs/proxy.pem"
key_path = "/etc/ssl/private/proxy.key"
https_port = 443  # Default: 443
```

**Option 3: ACME (Let's Encrypt)**

Automatically provision and renew certificates from Let's Encrypt:

```toml
[tls]
mode = "acme"
email = "admin@example.com"
domains = ["proxy.example.com", "api.example.com"]
# Use staging for testing (avoids rate limits):
# directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
https_port = 443           # Default: 443
http_challenge_port = 80   # Default: 80
```

**ACME Requirements:**
- Port 80 must be accessible from the internet for HTTP-01 challenges
- DNS must point to this server for all configured domains
- A valid email address for Let's Encrypt notifications

**Note:** On first startup with ACME mode, a temporary self-signed certificate is used until the real certificate is provisioned (typically within seconds). The proxy starts an additional HTTP server on `http_challenge_port` to handle ACME domain validation.

### Command Line Options

All configuration can also be specified via CLI flags or environment variables. The precedence order is: CLI > Environment Variable > Config File > Default.

#### General Options

| CLI Flag | Environment Variable | Description | Default |
|----------|---------------------|-------------|---------|
| `-c, --config <FILE>` | `CLAUDE_PROXY_CONFIG_FILE` | Path to configuration file | (see config file discovery) |
| `-v, --verbose` | - | Enable verbose (debug) logging | `false` |

#### Server Options

| CLI Flag | Environment Variable | Description | Default |
|----------|---------------------|-------------|---------|
| `--bind-address <ADDRESS>` | `CLAUDE_PROXY__BIND_ADDRESS` | Address to bind the server to | `0.0.0.0` |
| `-p, --port <PORT>` | `CLAUDE_PROXY__PORT` | Port to listen on | `8080` |
| `--upstream-url <URL>` | `CLAUDE_PROXY__UPSTREAM_URL` | Upstream API URL | (required) |
| `--client-api-key <KEY>` | `CLAUDE_PROXY__CLIENT_API_KEY` | API key clients must provide | (required) |

#### Upstream Authentication Options

| CLI Flag | Environment Variable | Description |
|----------|---------------------|-------------|
| `--upstream-auth-type <TYPE>` | `CLAUDE_PROXY__UPSTREAM_AUTH__TYPE` | Auth type: `api_key`, `azure_ad`, `azure_cli`, `azure_managed_identity` |
| `--upstream-api-key <KEY>` | `CLAUDE_PROXY__UPSTREAM_AUTH__API_KEY` | API key (when type=`api_key`) |
| `--azure-tenant-id <ID>` | `CLAUDE_PROXY__UPSTREAM_AUTH__TENANT_ID` | Azure AD tenant ID (when type=`azure_ad`) |
| `--azure-client-id <ID>` | `CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_ID` | Azure AD/managed identity client ID |
| `--azure-client-secret <SECRET>` | `CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_SECRET` | Azure AD client secret (when type=`azure_ad`) |
| `--azure-scope <SCOPE>` | `CLAUDE_PROXY__UPSTREAM_AUTH__SCOPE` | Azure scope (default: `https://ai.azure.com/.default`) |
| - | `CLAUDE_PROXY__UPSTREAM_AUTH__RESOURCE` | Azure managed identity resource (when type=`azure_managed_identity`) |

#### Logging Options

| CLI Flag | Environment Variable | Description | Default |
|----------|---------------------|-------------|---------|
| `--log-path <PATH>` | `CLAUDE_PROXY__LOGGING__LOG_PATH` | Directory for log files | (stdout only) |
| `--log-rotation <ROTATION>` | `CLAUDE_PROXY__LOGGING__ROTATION` | Log rotation: `hourly`, `daily` | `daily` |
| `--log-level <LEVEL>` | `CLAUDE_PROXY__LOGGING__LEVEL` | Log level: `trace`, `debug`, `info`, `warn`, `error` | `info` |
| `--log-prefix <PREFIX>` | `CLAUDE_PROXY__LOGGING__LOG_PREFIX` | Prefix for log file names | `claude-proxy` |

#### TLS Options

| CLI Flag | Environment Variable | Description | Default |
|----------|---------------------|-------------|---------|
| `--tls-mode <MODE>` | `CLAUDE_PROXY__TLS__MODE` | TLS mode: `disabled`, `manual`, `acme` | `disabled` |
| `--tls-cert-path <PATH>` | `CLAUDE_PROXY__TLS__CERT_PATH` | Path to TLS certificate file (manual mode) | - |
| `--tls-key-path <PATH>` | `CLAUDE_PROXY__TLS__KEY_PATH` | Path to TLS private key file (manual mode) | - |
| `--https-port <PORT>` | `CLAUDE_PROXY__TLS__HTTPS_PORT` | HTTPS listen port | `443` |
| `--acme-email <EMAIL>` | `CLAUDE_PROXY__TLS__EMAIL` | ACME contact email (acme mode) | - |
| `--acme-domains <DOMAINS>` | `CLAUDE_PROXY__TLS__DOMAINS` | ACME domains (comma-separated) | - |
| `--acme-directory-url <URL>` | `CLAUDE_PROXY__TLS__DIRECTORY_URL` | ACME directory URL | Let's Encrypt production |
| `--acme-cache-dir <PATH>` | `CLAUDE_PROXY__TLS__CACHE_DIR` | ACME cache directory | Platform-specific |
| `--http-challenge-port <PORT>` | `CLAUDE_PROXY__TLS__HTTP_CHALLENGE_PORT` | HTTP port for ACME challenges | `80` |

#### Example: Running without a config file

```bash
claude-proxy \
  --upstream-url "https://your-resource.services.ai.azure.com" \
  --client-api-key "your-client-key" \
  --upstream-auth-type azure_cli
```

Or using environment variables:

```bash
export CLAUDE_PROXY__UPSTREAM_URL="https://your-resource.services.ai.azure.com"
export CLAUDE_PROXY__CLIENT_API_KEY="your-client-key"
export CLAUDE_PROXY__UPSTREAM_AUTH__TYPE="azure_cli"
claude-proxy
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
