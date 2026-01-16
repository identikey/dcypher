use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)] // Will be used by route handlers
pub enum ServerError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Nonce invalid or already used")]
    NonceInvalid,

    #[error("Signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServerError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            ServerError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ServerError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            ServerError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ServerError::NonceInvalid => {
                (StatusCode::BAD_REQUEST, "Invalid or expired nonce".into())
            }
            ServerError::SignatureInvalid(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            ServerError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".into(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

#[allow(dead_code)] // Will be used by route handlers
pub type ServerResult<T> = Result<T, ServerError>;
