//! Storage trait definitions

use async_trait::async_trait;
use blake3::Hash;

use crate::error::StorageResult;

/// Encode a Blake3 hash as base58 (compact, readable)
pub fn hash_to_base58(hash: &Hash) -> String {
    bs58::encode(hash.as_bytes()).into_string()
}

/// Decode base58 to Blake3 hash
pub fn hash_from_base58(s: &str) -> Option<Hash> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Hash::from(arr))
}

/// Content-addressed chunk storage
///
/// All operations are keyed by Blake3 hash. Implementations must verify
/// that stored data matches the provided hash (integrity guarantee).
#[async_trait]
pub trait ChunkStorage: Send + Sync {
    /// Store a chunk by its hash
    ///
    /// Implementations MUST verify that `blake3::hash(data) == hash`.
    /// Returns `StorageError::HashMismatch` if verification fails.
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()>;

    /// Retrieve a chunk by hash
    ///
    /// Returns `StorageError::NotFound` if the chunk doesn't exist.
    /// Implementations SHOULD verify hash on retrieval (defense in depth).
    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>>;

    /// Check if a chunk exists
    async fn exists(&self, hash: &Hash) -> StorageResult<bool>;

    /// Delete a chunk
    ///
    /// Returns `Ok(())` even if the chunk didn't exist (idempotent).
    async fn delete(&self, hash: &Hash) -> StorageResult<()>;

    /// List all chunk hashes (primarily for testing/debugging)
    ///
    /// Production implementations may return an error or partial results
    /// for very large stores.
    async fn list(&self) -> StorageResult<Vec<Hash>>;
}
