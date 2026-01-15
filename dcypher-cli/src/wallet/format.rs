use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAGIC: &[u8; 4] = b"DCYW";
const VERSION: u8 = 1;

// Argon2 params (OWASP recommendations)
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallelism

#[derive(Serialize, Deserialize, Debug)]
pub struct WalletData {
    pub version: u8,
    pub identities: HashMap<String, Identity>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity {
    pub created_at: u64,
    pub fingerprint: String,
    pub ed25519: KeyPair,
    pub ml_dsa: KeyPair,
    pub pre: KeyPair,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPair {
    pub public: String, // base58
    pub secret: String, // base58
}

impl WalletData {
    pub fn new() -> Self {
        Self {
            version: 1,
            identities: HashMap::new(),
        }
    }
}

impl Default for WalletData {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encrypt_wallet(data: &WalletData, password: &str) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(data)?;

    // Generate salt and nonce
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive key with Argon2id
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e:?}"))?;

    // Encrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), json.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    // Assemble: magic || version || salt || nonce || ciphertext (includes tag)
    let mut output = Vec::with_capacity(4 + 1 + 32 + 24 + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt_wallet(data: &[u8], password: &str) -> Result<WalletData> {
    if data.len() < 4 + 1 + 32 + 24 + 16 {
        return Err(anyhow!("Wallet file too short"));
    }

    // Parse header
    if &data[0..4] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let version = data[4];
    if version != VERSION {
        return Err(anyhow!("Unsupported wallet version: {version}"));
    }

    let salt = &data[5..37];
    let nonce = &data[37..61];
    let ciphertext = &data[61..];

    // Derive key
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e:?}"))?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let nonce_arr: [u8; 24] = nonce.try_into()?;
    let plaintext = cipher
        .decrypt(&nonce_arr.into(), ciphertext)
        .map_err(|_| anyhow!("Decryption failed (wrong password?)"))?;

    let wallet: WalletData = serde_json::from_slice(&plaintext)?;
    Ok(wallet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_encryption_roundtrip() {
        let mut wallet = WalletData::new();
        wallet.identities.insert(
            "test".to_string(),
            Identity {
                created_at: 1704067200,
                fingerprint: "test-fp".to_string(),
                ed25519: KeyPair {
                    public: "test-pub".to_string(),
                    secret: "test-sec".to_string(),
                },
                ml_dsa: KeyPair {
                    public: "test-pub".to_string(),
                    secret: "test-sec".to_string(),
                },
                pre: KeyPair {
                    public: "test-pub".to_string(),
                    secret: "test-sec".to_string(),
                },
            },
        );

        let password = "test-password-123";
        let encrypted = encrypt_wallet(&wallet, password).unwrap();
        let decrypted = decrypt_wallet(&encrypted, password).unwrap();

        assert_eq!(wallet.version, decrypted.version);
        assert_eq!(wallet.identities.len(), decrypted.identities.len());
    }

    #[test]
    fn test_wrong_password_fails() {
        let wallet = WalletData::new();
        let encrypted = encrypt_wallet(&wallet, "correct-password").unwrap();
        let result = decrypt_wallet(&encrypted, "wrong-password");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong password"));
    }

    #[test]
    fn test_invalid_magic_fails() {
        let wallet = WalletData::new();
        let mut encrypted = encrypt_wallet(&wallet, "password").unwrap();
        encrypted[0] = b'X'; // Corrupt magic bytes

        let result = decrypt_wallet(&encrypted, "password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad magic"));
    }
}
