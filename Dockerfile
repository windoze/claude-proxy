# Build stage
FROM --platform=$BUILDPLATFORM rust:1.83-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install build dependencies for musl
RUN apk add --no-cache musl-dev

# Determine the Rust target based on TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") echo "x86_64-unknown-linux-musl" > /tmp/rust_target ;; \
      "linux/arm64") echo "aarch64-unknown-linux-musl" > /tmp/rust_target ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac

# Install the appropriate Rust target
RUN rustup target add $(cat /tmp/rust_target)

# Create a new empty shell project
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release --target $(cat /tmp/rust_target) || true

# Remove the dummy source
RUN rm -rf src

# Copy actual source code
COPY src ./src

# Touch main.rs to ensure it gets rebuilt
RUN touch src/main.rs

# Build the actual application
RUN cargo build --release --target $(cat /tmp/rust_target) && \
    cp target/$(cat /tmp/rust_target)/release/claude-proxy /app/claude-proxy

# Runtime stage
FROM alpine:3.21

# Install tini for proper init handling
RUN apk add --no-cache tini ca-certificates

# Create non-root user
RUN addgroup -g 1000 claude-proxy && \
    adduser -u 1000 -G claude-proxy -s /bin/sh -D claude-proxy

# Copy the binary from builder
COPY --from=builder /app/claude-proxy /usr/local/bin/claude-proxy

# Make binary executable
RUN chmod +x /usr/local/bin/claude-proxy

# Create directories for TLS/ACME (optional, only needed if using TLS)
# These can be mounted as volumes if persistence is required
RUN mkdir -p /var/lib/claude-proxy/acme && \
    chown -R claude-proxy:claude-proxy /var/lib/claude-proxy

# Switch to non-root user
USER claude-proxy

# Default ports
# 8080 - HTTP proxy (default)
# 443  - HTTPS proxy (when TLS enabled)
# 80   - ACME HTTP-01 challenge server (when ACME enabled)
EXPOSE 8080 443 80

# Environment variables for configuration
# Required (must be set):
#   CLAUDE_PROXY__UPSTREAM_URL - Upstream API URL
#   CLAUDE_PROXY__CLIENT_API_KEY - API key clients must provide
#   CLAUDE_PROXY__UPSTREAM_AUTH__TYPE - Auth type: api_key, azure_ad, azure_cli, azure_managed_identity
#
# For api_key auth type:
#   CLAUDE_PROXY__UPSTREAM_AUTH__API_KEY - Upstream API key
#
# For azure_ad auth type:
#   CLAUDE_PROXY__UPSTREAM_AUTH__TENANT_ID - Azure AD tenant ID
#   CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_ID - Azure AD client ID
#   CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_SECRET - Azure AD client secret
#   CLAUDE_PROXY__UPSTREAM_AUTH__SCOPE - Azure scope (default: https://ai.azure.com/.default)
#
# For azure_managed_identity auth type:
#   CLAUDE_PROXY__UPSTREAM_AUTH__CLIENT_ID - (optional) Managed identity client ID
#   CLAUDE_PROXY__UPSTREAM_AUTH__RESOURCE - Azure resource (default: https://ai.azure.com/.default)
#
# Optional:
#   CLAUDE_PROXY__BIND_ADDRESS - Bind address (default: 0.0.0.0)
#   CLAUDE_PROXY__PORT - Port (default: 8080)
#   CLAUDE_PROXY__LOGGING__LOG_PATH - Directory for log files
#   CLAUDE_PROXY__LOGGING__ROTATION - Log rotation: hourly or daily (default: daily)
#   CLAUDE_PROXY__LOGGING__LEVEL - Log level: trace, debug, info, warn, error (default: info)
#   CLAUDE_PROXY__LOGGING__LOG_PREFIX - Log file prefix (default: claude-proxy)
#
# TLS Configuration (optional):
#   CLAUDE_PROXY__TLS__MODE - TLS mode: disabled, manual, acme (default: disabled)
#
# For manual TLS mode:
#   CLAUDE_PROXY__TLS__CERT_PATH - Path to PEM certificate file
#   CLAUDE_PROXY__TLS__KEY_PATH - Path to PEM private key file
#   CLAUDE_PROXY__TLS__HTTPS_PORT - HTTPS listen port (default: 443)
#
# For ACME (Let's Encrypt) mode:
#   CLAUDE_PROXY__TLS__EMAIL - Contact email for ACME account (required)
#   CLAUDE_PROXY__TLS__DOMAINS - Comma-separated list of domains (required)
#   CLAUDE_PROXY__TLS__DIRECTORY_URL - ACME directory URL (default: Let's Encrypt production)
#   CLAUDE_PROXY__TLS__CACHE_DIR - Directory to cache certs (default: /var/lib/claude-proxy/acme)
#   CLAUDE_PROXY__TLS__HTTPS_PORT - HTTPS listen port (default: 443)
#   CLAUDE_PROXY__TLS__HTTP_CHALLENGE_PORT - HTTP port for ACME challenges (default: 80)
#
# Note: For ACME mode, port 80 must be accessible from the internet for HTTP-01 challenges.
# When running in Docker, you may need to use --network=host or ensure proper port mapping.

# Use tini as entrypoint for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Run the application
CMD ["claude-proxy"]
