use crate::error::{ServerError, ServerResult};
use crate::middleware::{extract_signature_headers, verify_multisig};
use crate::state::{Account, AppState};
use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub ed25519_pk: String,     // base58
    pub ml_dsa_pk: String,      // base58
    pub pre_pk: Option<String>, // base58, optional
}

#[derive(Serialize)]
pub struct AccountResponse {
    pub fingerprint: String,
    pub ed25519_pk: String,
    pub ml_dsa_pk: String,
    pub pre_pk: Option<String>,
    pub created_at: u64,
}

/// POST /accounts
pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateAccountRequest>,
) -> ServerResult<(StatusCode, Json<AccountResponse>)> {
    let sig_headers = extract_signature_headers(&headers)?;

    // Decode keys
    let ed25519_pk = bs58::decode(&body.ed25519_pk)
        .into_vec()
        .map_err(|_| ServerError::BadRequest("Invalid base58 in ed25519_pk".into()))?;
    let ml_dsa_pk = bs58::decode(&body.ml_dsa_pk)
        .into_vec()
        .map_err(|_| ServerError::BadRequest("Invalid base58 in ml_dsa_pk".into()))?;
    let pre_pk = body
        .pre_pk
        .as_ref()
        .map(|s| bs58::decode(s).into_vec())
        .transpose()
        .map_err(|_| ServerError::BadRequest("Invalid base58 in pre_pk".into()))?;

    // Compute fingerprint from ED25519 public key
    let fingerprint = compute_fingerprint(&ed25519_pk);

    // Verify fingerprint matches header
    if fingerprint != sig_headers.fingerprint {
        return Err(ServerError::BadRequest(
            "X-Public-Key fingerprint doesn't match ed25519_pk".into(),
        ));
    }

    // Build message to verify
    let message = format!(
        "CREATE:{}:{}:{}:{}",
        body.ed25519_pk,
        body.ml_dsa_pk,
        body.pre_pk.as_deref().unwrap_or(""),
        sig_headers.nonce
    );

    // Verify signature
    verify_multisig(message.as_bytes(), &sig_headers, &ed25519_pk, &ml_dsa_pk)?;

    // Check for conflict
    {
        let accounts = state.accounts.read().await;
        if accounts.accounts.contains_key(&fingerprint) {
            return Err(ServerError::Conflict("Account already exists".into()));
        }
    }

    // Create account
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let account = Account {
        fingerprint: fingerprint.clone(),
        ed25519_pk: ed25519_pk.clone(),
        ml_dsa_pk: ml_dsa_pk.clone(),
        pre_pk: pre_pk.clone(),
        created_at: now,
    };

    {
        let mut accounts = state.accounts.write().await;
        accounts.accounts.insert(fingerprint.clone(), account);
    }

    Ok((
        StatusCode::CREATED,
        Json(AccountResponse {
            fingerprint,
            ed25519_pk: body.ed25519_pk,
            ml_dsa_pk: body.ml_dsa_pk,
            pre_pk: body.pre_pk,
            created_at: now,
        }),
    ))
}

/// GET /accounts/{fingerprint}
pub async fn get_account(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> ServerResult<Json<AccountResponse>> {
    let accounts = state.accounts.read().await;
    let account = accounts
        .accounts
        .get(&fingerprint)
        .ok_or_else(|| ServerError::NotFound("Account not found".into()))?;

    Ok(Json(AccountResponse {
        fingerprint: account.fingerprint.clone(),
        ed25519_pk: bs58::encode(&account.ed25519_pk).into_string(),
        ml_dsa_pk: bs58::encode(&account.ml_dsa_pk).into_string(),
        pre_pk: account
            .pre_pk
            .as_ref()
            .map(|pk| bs58::encode(pk).into_string()),
        created_at: account.created_at,
    }))
}

/// Compute fingerprint from public key bytes
fn compute_fingerprint(pk: &[u8]) -> String {
    let hash = blake3::hash(pk);
    bs58::encode(hash.as_bytes()).into_string()
}
