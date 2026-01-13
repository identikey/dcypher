use crate::state::AppState;
use axum::{Json, extract::State};
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct NonceResponse {
    pub nonce: String,
    pub expires_at: u64,
}

pub async fn get_nonce(State(state): State<AppState>) -> Json<NonceResponse> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let nonce = format!("{}:{}", now_ms, Uuid::new_v4());
    let expires_at = now_ms / 1000 + state.config.nonce.window_secs;

    Json(NonceResponse { nonce, expires_at })
}
