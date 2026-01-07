//! Ownership tracking: who owns which files

use async_trait::async_trait;
use blake3::Hash;

use crate::capability::Operation;
use crate::error::AuthResult;
use crate::fingerprint::PublicKeyFingerprint;
use crate::grant::AccessGrant;

/// Tracks file ownership and access grants
#[async_trait]
pub trait OwnershipStore: Send + Sync {
    /// Register a new file as owned by a public key
    ///
    /// Returns error if file is already registered to a different owner.
    async fn register(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()>;

    /// Check if a public key owns a file
    async fn is_owner(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<bool>;

    /// List all files owned by a public key
    async fn list_owned(&self, owner: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>>;

    /// Transfer ownership to another public key
    ///
    /// Only the current owner can transfer.
    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()>;

    /// Grant access to another public key
    async fn grant_access(&self, grant: AccessGrant) -> AuthResult<()>;

    /// Revoke access from a grantee
    async fn revoke_access(
        &self,
        owner: &PublicKeyFingerprint,
        grantee: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()>;

    /// Check if a public key has access (owner or grantee)
    async fn has_access(
        &self,
        pubkey: &PublicKeyFingerprint,
        file_hash: &Hash,
        operation: Operation,
    ) -> AuthResult<bool>;

    /// List all grants for a file (owner only)
    async fn list_grants(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<Vec<AccessGrant>>;

    /// List files shared with a public key (as grantee)
    async fn list_shared_with(&self, grantee: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>>;

    /// Remove file record entirely (for cleanup)
    async fn unregister(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()>;
}
