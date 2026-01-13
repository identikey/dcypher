use crate::error::{ServerError, ServerResult};
use crate::middleware::{extract_signature_headers, verify_multisig};
use crate::state::AppState;
use axum::{
    Json,
    body::Body,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use dcypher_storage::{hash_from_base58, hash_to_base58};
use serde::Serialize;

#[derive(Serialize)]
pub struct UploadResponse {
    pub hash: String,
    pub size: usize,
}

/// POST /files
/// Upload a file (body is raw bytes, hash computed server-side)
pub async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ServerResult<(StatusCode, Json<UploadResponse>)> {
    let sig_headers = extract_signature_headers(&headers)?;

    // Look up uploader's account
    let account = {
        let accounts = state.accounts.read().await;
        accounts
            .accounts
            .get(&sig_headers.fingerprint)
            .ok_or_else(|| ServerError::NotFound("Account not found".into()))?
            .clone()
    };

    // Compute hash
    let hash = blake3::hash(&body);
    let hash_str = hash_to_base58(&hash);

    // Verify signature: "UPLOAD:{fingerprint}:{hash}:{nonce}"
    let message = format!(
        "UPLOAD:{}:{}:{}",
        sig_headers.fingerprint, hash_str, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &account.ed25519_pk,
        &account.ml_dsa_pk,
    )?;

    let size = body.len();

    // Store
    state
        .storage
        .put(&hash, &body)
        .await
        .map_err(|e| ServerError::Internal(format!("Storage error: {e}")))?;

    // Register ownership
    let fingerprint = identikey_storage_auth::PublicKeyFingerprint::from_bytes(
        *blake3::hash(&account.ed25519_pk).as_bytes(),
    );
    state
        .ownership
        .register(&fingerprint, &hash)
        .await
        .map_err(|e| ServerError::Internal(format!("Ownership error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            hash: hash_str,
            size,
        }),
    ))
}

/// GET /files/{hash}
pub async fn download_file(
    State(state): State<AppState>,
    Path(hash_str): Path<String>,
) -> ServerResult<Response> {
    let hash = hash_from_base58(&hash_str)
        .ok_or_else(|| ServerError::BadRequest("Invalid hash".into()))?;

    let data = state.storage.get(&hash).await.map_err(|e| match e {
        dcypher_storage::StorageError::NotFound(_) => {
            ServerError::NotFound("File not found".into())
        }
        other => ServerError::Internal(other.to_string()),
    })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, data.len())
        .header("X-Content-Hash", hash_str)
        .body(Body::from(data))
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    Ok(response)
}

/// DELETE /files/{hash}
pub async fn delete_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash_str): Path<String>,
) -> ServerResult<StatusCode> {
    let sig_headers = extract_signature_headers(&headers)?;

    let hash = hash_from_base58(&hash_str)
        .ok_or_else(|| ServerError::BadRequest("Invalid hash".into()))?;

    // Look up account
    let account = {
        let accounts = state.accounts.read().await;
        accounts
            .accounts
            .get(&sig_headers.fingerprint)
            .ok_or_else(|| ServerError::NotFound("Account not found".into()))?
            .clone()
    };

    // Verify ownership
    let fingerprint = identikey_storage_auth::PublicKeyFingerprint::from_bytes(
        *blake3::hash(&account.ed25519_pk).as_bytes(),
    );

    let is_owner = state
        .ownership
        .is_owner(&fingerprint, &hash)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    if !is_owner {
        return Err(ServerError::Unauthorized("Not the file owner".into()));
    }

    // Verify signature
    let message = format!(
        "DELETE:{}:{}:{}",
        sig_headers.fingerprint, hash_str, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &account.ed25519_pk,
        &account.ml_dsa_pk,
    )?;

    // Delete
    state
        .storage
        .delete(&hash)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    // Unregister ownership
    state
        .ownership
        .unregister(&fingerprint, &hash)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
