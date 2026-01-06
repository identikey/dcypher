use super::{BackendId, Ciphertext, KeyPair, PublicKey, RecryptKey, SecretKey};
use crate::error::PreResult;
use zeroize::Zeroizing;

/// A proxy recryption backend
///
/// Abstracts over different PRE schemes (lattice post-quantum, EC classical).
/// All operations are semantic—ciphertext bytes may differ between runs.
///
/// Note: Send + Sync bounds will be added in Phase 3 once threading model is finalized.
pub trait PreBackend {
    /// Backend identifier for serialization format detection
    fn backend_id(&self) -> BackendId;

    /// Human-readable name
    fn name(&self) -> &'static str;

    /// Whether this backend is post-quantum secure
    fn is_post_quantum(&self) -> bool;

    /// Generate a new keypair
    fn generate_keypair(&self) -> PreResult<KeyPair>;

    /// Derive public key from secret key (if deterministic)
    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey>;

    /// Generate a recryption key from delegator to delegatee
    ///
    /// Allows transforming ciphertexts encrypted for `from_secret`'s
    /// public key into ciphertexts decryptable by `to_public`'s secret key.
    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey>;

    /// Encrypt data for a recipient
    ///
    /// For hybrid encryption, plaintext is always 96 bytes (KeyMaterial bundle).
    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext>;

    /// Decrypt data using secret key
    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext)
    -> PreResult<Zeroizing<Vec<u8>>>;

    /// Transform a ciphertext for a new recipient
    ///
    /// Uses recrypt key to transform without revealing plaintext.
    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext>;

    /// Maximum plaintext size this backend can encrypt directly
    fn max_plaintext_size(&self) -> usize;

    /// Approximate ciphertext size for given plaintext size
    fn ciphertext_size_estimate(&self, plaintext_size: usize) -> usize;
}
