use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::warn;

/// State for API key validation middleware
#[derive(Clone)]
pub struct ApiKeyValidatorState {
    pub expected_api_key: String,
}

/// Middleware to validate client API key
pub async fn validate_client_api_key(
    State(state): State<ApiKeyValidatorState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract API key from request headers
    // Support both x-api-key header and Authorization: Bearer token
    let api_key = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        });

    match api_key {
        Some(key) if key == state.expected_api_key => {
            // API key is valid, proceed with the request
            Ok(next.run(request).await)
        }
        Some(_) => {
            warn!("Invalid API key provided");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            warn!("No API key provided");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
