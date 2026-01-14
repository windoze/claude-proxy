use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderName};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info};

use crate::auth::UpstreamAuth;

/// Shared state for the proxy
#[derive(Clone)]
pub struct ProxyState {
    pub upstream_url: String,
    pub upstream_auth: Arc<dyn UpstreamAuth>,
    pub http_client: reqwest::Client,
}

/// Headers that should not be forwarded to the upstream
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
];

/// Headers that we handle specially
const SPECIAL_HEADERS: &[&str] = &["x-api-key", "authorization"];

/// Proxy handler that forwards requests to the Claude API
pub async fn proxy_handler(
    State(state): State<ProxyState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path();
    let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

    info!("Proxying {} {}{}", method, path, query);

    // Log request details at debug level
    debug!("Request headers:");
    for (name, value) in request.headers() {
        let name_str = name.as_str().to_lowercase();
        // Mask sensitive headers
        if name_str == "x-api-key" || name_str == "authorization" {
            debug!("  {}: [REDACTED]", name);
        } else {
            debug!("  {}: {:?}", name, value);
        }
    }

    // Build the upstream URL
    let upstream_url = format!("{}{}{}", state.upstream_url, path, query);

    // Get auth header for upstream
    let auth_header = match state.upstream_auth.get_auth_header().await {
        Ok(header) => header,
        Err(e) => {
            error!("Failed to get upstream auth header: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Authentication error: {}", e)))
                .unwrap();
        }
    };

    // Build headers for upstream request
    let mut upstream_headers = HeaderMap::new();

    // Copy headers from original request, excluding hop-by-hop and special headers
    for (name, value) in request.headers() {
        let name_str = name.as_str().to_lowercase();
        if !HOP_BY_HOP_HEADERS.contains(&name_str.as_str())
            && !SPECIAL_HEADERS.contains(&name_str.as_str())
        {
            upstream_headers.insert(name.clone(), value.clone());
        }
    }

    // Add the upstream authentication header using the appropriate header name
    let auth_header_name = state.upstream_auth.auth_header_name();
    upstream_headers.insert(
        HeaderName::from_static(auth_header_name),
        auth_header,
    );

    // Get additional headers from auth provider
    match state.upstream_auth.get_additional_headers().await {
        Ok(additional) => {
            for (name, value) in additional {
                if let Ok(header_name) = HeaderName::try_from(name) {
                    upstream_headers.insert(header_name, value);
                }
            }
        }
        Err(e) => {
            error!("Failed to get additional auth headers: {}", e);
        }
    }

    // Read the request body
    let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Failed to read request body: {}", e)))
                .unwrap();
        }
    };

    // Log request body at debug level
    debug!("Request body size: {} bytes", body_bytes.len());
    if !body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            // Try to parse as JSON for prettier logging
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                // Log a summary of the JSON request
                if let Some(model) = json.get("model") {
                    debug!("  model: {}", model);
                }
                if let Some(max_tokens) = json.get("max_tokens") {
                    debug!("  max_tokens: {}", max_tokens);
                }
                if let Some(stream) = json.get("stream") {
                    debug!("  stream: {}", stream);
                }
                if let Some(messages) = json.get("messages").and_then(|m| m.as_array()) {
                    debug!("  messages: {} message(s)", messages.len());
                }
            }
        }
    }

    // Build and send the upstream request
    let upstream_request = state
        .http_client
        .request(method, &upstream_url)
        .headers(upstream_headers)
        .body(body_bytes);

    let upstream_response = match upstream_request.send().await {
        Ok(response) => response,
        Err(e) => {
            error!("Upstream request failed: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Upstream request failed: {}", e)))
                .unwrap();
        }
    };

    // Build response headers
    let status = upstream_response.status();
    debug!("Upstream response status: {}", status);

    let mut response_headers = HeaderMap::new();

    for (name, value) in upstream_response.headers() {
        let name_str = name.as_str().to_lowercase();
        if !HOP_BY_HOP_HEADERS.contains(&name_str.as_str()) {
            response_headers.insert(name.clone(), value.clone());
        }
    }

    // Check if this is a streaming response
    let is_streaming = response_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/event-stream"))
        .unwrap_or(false);

    if is_streaming {
        // Handle streaming response
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);

        let mut byte_stream = upstream_response.bytes_stream();
        tokio::spawn(async move {
            while let Some(chunk) = byte_stream.next().await {
                match chunk {
                    Ok(bytes) => {
                        if tx.send(Ok(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                        break;
                    }
                }
            }
        });

        let stream = ReceiverStream::new(rx);
        let body = Body::from_stream(stream);

        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        response
    } else {
        // Handle non-streaming response
        let body_bytes = match upstream_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read upstream response: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(format!(
                        "Failed to read upstream response: {}",
                        e
                    )))
                    .unwrap();
            }
        };

        let mut response = Response::new(Body::from(body_bytes));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        response
    }
}
