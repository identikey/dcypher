use crate::error::{ServerError, ServerResult};
use crate::middleware::{extract_signature_headers, verify_multisig};
use crate::state::{AppState, SharePolicy};
use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use recrypt_core::pre::BackendId;
use recrypt_core::{EncryptedFile, HybridEncryptor};
use recrypt_proto::MultiFormat;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateShareRequest {
    pub to_fingerprint: String,
    pub file_hash: String,   // base58
    pub recrypt_key: String, // base58
    pub backend_id: String,  // "mock" or "lattice"
}

#[derive(Serialize)]
pub struct ShareResponse {
    pub share_id: String,
    pub from: String,
    pub to: String,
    pub file_hash: String,
    pub created_at: u64,
}

/// POST /recryption/share
pub async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateShareRequest>,
) -> ServerResult<(StatusCode, Json<ShareResponse>)> {
    let sig_headers = extract_signature_headers(&headers)?;
    let from_fingerprint = sig_headers.fingerprint.clone();

    // Look up sender's account
    let sender_account = {
        let accounts = state.accounts.read().await;
        accounts
            .accounts
            .get(&from_fingerprint)
            .ok_or_else(|| ServerError::NotFound("Sender account not found".into()))?
            .clone()
    };

    // Verify recipient exists
    {
        let accounts = state.accounts.read().await;
        if !accounts.accounts.contains_key(&body.to_fingerprint) {
            return Err(ServerError::NotFound("Recipient account not found".into()));
        }
    }

    // Parse file hash
    let file_hash = recrypt_storage::hash_from_base58(&body.file_hash)
        .ok_or_else(|| ServerError::BadRequest("Invalid file hash".into()))?;

    // Verify file exists
    if !state
        .storage
        .exists(&file_hash)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?
    {
        return Err(ServerError::NotFound("File not found".into()));
    }

    // Build and verify signature
    let message = format!(
        "SHARE:{}:{}:{}:{}",
        from_fingerprint, body.to_fingerprint, body.file_hash, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &sender_account.ed25519_pk,
        &sender_account.ml_dsa_pk,
    )?;

    // Decode recrypt key
    let recrypt_key_bytes = bs58::decode(&body.recrypt_key)
        .into_vec()
        .map_err(|_| ServerError::BadRequest("Invalid base58 in recrypt_key".into()))?;

    // Parse backend ID
    let backend_id: BackendId = body
        .backend_id
        .parse()
        .map_err(|_| ServerError::BadRequest(format!("Invalid backend_id: {}", body.backend_id)))?;

    // Generate share ID
    let share_data = format!(
        "{}:{}:{}",
        from_fingerprint, body.to_fingerprint, body.file_hash
    );
    let share_id = bs58::encode(blake3::hash(share_data.as_bytes()).as_bytes()).into_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let policy = SharePolicy {
        id: share_id.clone(),
        from_fingerprint: from_fingerprint.clone(),
        to_fingerprint: body.to_fingerprint.clone(),
        file_hash,
        recrypt_key: recrypt_key_bytes,
        backend_id,
        created_at: now,
    };

    {
        let mut shares = state.shares.write().await;
        shares.shares.insert(share_id.clone(), policy);
    }

    Ok((
        StatusCode::CREATED,
        Json(ShareResponse {
            share_id,
            from: from_fingerprint,
            to: body.to_fingerprint,
            file_hash: body.file_hash,
            created_at: now,
        }),
    ))
}

/// GET /recryption/share/{id}/file
/// Downloads file with recryption transformation applied
pub async fn download_recrypted(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ServerResult<Response> {
    let sig_headers = extract_signature_headers(&headers)?;
    let requester_fingerprint = sig_headers.fingerprint.clone();

    // Look up share
    let policy = {
        let shares = state.shares.read().await;
        shares
            .shares
            .get(&share_id)
            .ok_or_else(|| ServerError::NotFound("Share not found".into()))?
            .clone()
    };

    // Verify requester is the intended recipient
    if policy.to_fingerprint != requester_fingerprint {
        return Err(ServerError::Unauthorized(
            "Not authorized for this share".into(),
        ));
    }

    // Look up requester's account for signature verification
    let requester_account = {
        let accounts = state.accounts.read().await;
        accounts
            .accounts
            .get(&requester_fingerprint)
            .ok_or_else(|| ServerError::NotFound("Requester account not found".into()))?
            .clone()
    };

    // Verify signature
    let message = format!(
        "DOWNLOAD:{}:{}:{}",
        requester_fingerprint, share_id, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &requester_account.ed25519_pk,
        &requester_account.ml_dsa_pk,
    )?;

    // Load the encrypted file
    let file_bytes = state
        .storage
        .get(&policy.file_hash)
        .await
        .map_err(|e| ServerError::Internal(format!("Storage error: {e}")))?;

    // === ACTUAL RECRYPTION TRANSFORM ===

    // 1. Deserialize EncryptedFile from protobuf
    let encrypted = EncryptedFile::from_protobuf(&file_bytes)
        .map_err(|e| ServerError::Internal(format!("Failed to deserialize file: {e}")))?;

    // 2. Reconstruct RecryptKey from stored bytes (includes embedded public keys)
    let recrypt_key = recrypt_core::pre::RecryptKey::from_bytes(&policy.recrypt_key)
        .map_err(|e| ServerError::Internal(format!("Failed to deserialize recrypt key: {e}")))?;

    // 3. Perform recryption (transforms wrapped_key only)
    let encryptor = HybridEncryptor::new(state.pre_backend.as_ref());
    let recrypted = encryptor
        .recrypt(&recrypt_key, &encrypted)
        .map_err(|e| ServerError::Internal(format!("Recryption failed: {e}")))?;

    // 4. Serialize back to protobuf
    let recrypted_bytes = recrypted
        .to_protobuf()
        .map_err(|e| ServerError::Internal(format!("Failed to serialize: {e}")))?;

    // === END RECRYPTION TRANSFORM ===

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("X-Share-Id", share_id)
        .header("X-Recrypted", "true")
        .header("X-Backend", policy.backend_id.to_string())
        .body(Body::from(recrypted_bytes))
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    Ok(response)
}

/// DELETE /recryption/share/{id}
pub async fn revoke_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ServerResult<StatusCode> {
    let sig_headers = extract_signature_headers(&headers)?;
    let requester_fingerprint = sig_headers.fingerprint.clone();

    // Look up share
    let policy = {
        let shares = state.shares.read().await;
        shares
            .shares
            .get(&share_id)
            .ok_or_else(|| ServerError::NotFound("Share not found".into()))?
            .clone()
    };

    // Verify requester is the owner
    if policy.from_fingerprint != requester_fingerprint {
        return Err(ServerError::Unauthorized(
            "Only owner can revoke share".into(),
        ));
    }

    // Look up requester's account
    let requester_account = {
        let accounts = state.accounts.read().await;
        accounts
            .accounts
            .get(&requester_fingerprint)
            .ok_or_else(|| ServerError::NotFound("Account not found".into()))?
            .clone()
    };

    // Verify signature
    let message = format!(
        "REVOKE:{}:{}:{}",
        requester_fingerprint, share_id, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &requester_account.ed25519_pk,
        &requester_account.ml_dsa_pk,
    )?;

    // Remove share
    {
        let mut shares = state.shares.write().await;
        shares.shares.remove(&share_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// GET /accounts/{fingerprint}/shares
/// List shares (from or to this fingerprint)
pub async fn list_shares(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
    headers: HeaderMap,
) -> ServerResult<Json<ShareListResponse>> {
    // Extract and verify signature
    let sig_headers = extract_signature_headers(&headers)?;

    // Verify requester owns this fingerprint
    if sig_headers.fingerprint != fingerprint {
        return Err(ServerError::Unauthorized(
            "Can only list your own shares".into(),
        ));
    }

    // Look up account
    let account = {
        let accounts = state.accounts.read().await;
        accounts
            .accounts
            .get(&fingerprint)
            .ok_or_else(|| ServerError::NotFound("Account not found".into()))?
            .clone()
    };

    // Verify signature
    let message = format!("LIST_SHARES:{}:{}", fingerprint, sig_headers.nonce);
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &account.ed25519_pk,
        &account.ml_dsa_pk,
    )?;

    // Filter shares
    let shares = state.shares.read().await;
    let outgoing: Vec<ShareInfo> = shares
        .shares
        .iter()
        .filter(|(_, policy)| policy.from_fingerprint == fingerprint)
        .map(|(id, policy)| ShareInfo {
            share_id: id.clone(),
            from_fingerprint: policy.from_fingerprint.clone(),
            to_fingerprint: policy.to_fingerprint.clone(),
            file_hash: bs58::encode(policy.file_hash.as_bytes()).into_string(),
            created_at: policy.created_at,
        })
        .collect();

    let incoming: Vec<ShareInfo> = shares
        .shares
        .iter()
        .filter(|(_, policy)| policy.to_fingerprint == fingerprint)
        .map(|(id, policy)| ShareInfo {
            share_id: id.clone(),
            from_fingerprint: policy.from_fingerprint.clone(),
            to_fingerprint: policy.to_fingerprint.clone(),
            file_hash: bs58::encode(policy.file_hash.as_bytes()).into_string(),
            created_at: policy.created_at,
        })
        .collect();

    Ok(Json(ShareListResponse { outgoing, incoming }))
}

#[derive(serde::Serialize)]
pub struct ShareListResponse {
    pub outgoing: Vec<ShareInfo>,
    pub incoming: Vec<ShareInfo>,
}

#[derive(serde::Serialize)]
pub struct ShareInfo {
    pub share_id: String,
    pub from_fingerprint: String,
    pub to_fingerprint: String,
    pub file_hash: String,
    pub created_at: u64,
}
