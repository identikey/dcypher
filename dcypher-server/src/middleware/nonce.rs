use crate::error::ServerError;
use crate::middleware::auth::extract_signature_headers;
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

/// Middleware that validates nonce freshness and marks as used
pub async fn validate_nonce(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ServerError> {
    let headers = extract_signature_headers(request.headers())?;

    // Validate nonce format and freshness
    {
        let nonces = state.nonces.read().await;
        if !nonces.validate(&headers.nonce) {
            return Err(ServerError::NonceInvalid);
        }
        if nonces.is_used(&headers.nonce) {
            return Err(ServerError::NonceInvalid);
        }
    }

    // Run the handler
    let response = next.run(request).await;

    // Mark nonce as used (only if request succeeded)
    if response.status().is_success() {
        let mut nonces = state.nonces.write().await;
        nonces.mark_used(headers.nonce);
    }

    Ok(response)
}
