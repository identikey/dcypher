//! Provider index: where files are stored

use async_trait::async_trait;
use blake3::Hash;

use crate::error::AuthResult;

/// A storage provider URL
pub type ProviderUrl = String;

/// Tracks file locations across storage providers
///
/// Enables hosting agility: files can be moved between providers
/// without breaking references.
#[async_trait]
pub trait ProviderIndex: Send + Sync {
    /// Register a file's location
    ///
    /// A file can be stored at multiple providers for redundancy.
    async fn register(&self, file_hash: &Hash, provider_url: &ProviderUrl) -> AuthResult<()>;

    /// Look up all locations for a file
    async fn lookup(&self, file_hash: &Hash) -> AuthResult<Vec<ProviderUrl>>;

    /// Update a file's location (migration)
    async fn update_location(
        &self,
        file_hash: &Hash,
        old_url: &ProviderUrl,
        new_url: &ProviderUrl,
    ) -> AuthResult<()>;

    /// Remove a location (file deleted from provider)
    async fn remove_location(&self, file_hash: &Hash, provider_url: &ProviderUrl)
    -> AuthResult<()>;

    /// Remove all locations for a file
    async fn unregister(&self, file_hash: &Hash) -> AuthResult<()>;

    /// Check if a file has any registered locations
    async fn exists(&self, file_hash: &Hash) -> AuthResult<bool>;

    /// List all files at a provider (for provider management)
    async fn list_at_provider(&self, provider_url: &ProviderUrl) -> AuthResult<Vec<Hash>>;
}
