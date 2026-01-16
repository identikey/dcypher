use crate::error::{ServerError, ServerResult};
use axum::http::header::HeaderMap;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

/// Verified request identity, inserted into request extensions
#[derive(Clone, Debug)]
#[allow(dead_code)] // Will be used by middleware
pub struct VerifiedIdentity {
    pub fingerprint: String,
    pub nonce: String,
}

/// Extract signature headers
pub fn extract_signature_headers(headers: &HeaderMap) -> ServerResult<SignatureHeaders> {
    let nonce = headers
        .get("X-Nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("Missing X-Nonce header".into()))?
        .to_string();

    let fingerprint = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("Missing X-Public-Key header".into()))?
        .to_string();

    let ed25519_sig = headers
        .get("X-Signature-Ed25519")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("Missing X-Signature-Ed25519 header".into()))?;

    let ml_dsa_sig = headers
        .get("X-Signature-MlDsa")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("Missing X-Signature-MlDsa header".into()))?;

    let ed25519_sig = BASE64
        .decode(ed25519_sig)
        .map_err(|_| ServerError::BadRequest("Invalid base64 in ED25519 signature".into()))?;

    let ml_dsa_sig = BASE64
        .decode(ml_dsa_sig)
        .map_err(|_| ServerError::BadRequest("Invalid base64 in ML-DSA signature".into()))?;

    Ok(SignatureHeaders {
        nonce,
        fingerprint,
        ed25519_sig,
        ml_dsa_sig,
    })
}

#[derive(Debug)]
pub struct SignatureHeaders {
    pub nonce: String,
    pub fingerprint: String,
    pub ed25519_sig: Vec<u8>,
    pub ml_dsa_sig: Vec<u8>,
}

/// Verify multi-signature against a message
pub fn verify_multisig(
    message: &[u8],
    headers: &SignatureHeaders,
    ed25519_pk: &[u8],
    ml_dsa_pk: &[u8],
) -> ServerResult<()> {
    use recrypt_core::sign::{MultiSig, VerifyingKeys, verify_message};
    use ed25519_dalek::{Signature as Ed25519Sig, VerifyingKey};

    // Parse ED25519 public key
    let ed_pk_arr: [u8; 32] = ed25519_pk
        .try_into()
        .map_err(|_| ServerError::BadRequest("Invalid ED25519 public key length".into()))?;
    let ed_verifying = VerifyingKey::from_bytes(&ed_pk_arr)
        .map_err(|e| ServerError::BadRequest(format!("Invalid ED25519 public key: {e}")))?;

    // Parse ED25519 signature
    let ed_sig_arr: [u8; 64] = headers
        .ed25519_sig
        .as_slice()
        .try_into()
        .map_err(|_| ServerError::BadRequest("Invalid ED25519 signature length".into()))?;
    let ed_sig = Ed25519Sig::from_bytes(&ed_sig_arr);

    let verifying_keys = VerifyingKeys {
        ed25519: ed_verifying,
        ml_dsa: ml_dsa_pk.to_vec(),
    };

    let multisig = MultiSig {
        ed25519_sig: ed_sig,
        ml_dsa_sig: headers.ml_dsa_sig.clone(),
    };

    verify_message(message, &multisig, &verifying_keys)
        .map_err(|e| ServerError::SignatureInvalid(e.to_string()))?;

    Ok(())
}
