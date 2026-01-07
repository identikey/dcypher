//! In-memory ownership store

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use async_trait::async_trait;
use blake3::Hash;

use crate::capability::Operation;
use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::grant::AccessGrant;
use crate::ownership::OwnershipStore;

/// In-memory ownership store for testing
#[derive(Default)]
pub struct InMemoryOwnershipStore {
    /// file_hash -> owner
    owners: RwLock<HashMap<Hash, PublicKeyFingerprint>>,
    /// (file_hash, grantee) -> AccessGrant
    grants: RwLock<HashMap<(Hash, PublicKeyFingerprint), AccessGrant>>,
}

impl InMemoryOwnershipStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered files
    pub fn file_count(&self) -> usize {
        self.owners.read().unwrap().len()
    }

    /// Number of active grants
    pub fn grant_count(&self) -> usize {
        self.grants.read().unwrap().len()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.owners.write().unwrap().clear();
        self.grants.write().unwrap().clear();
    }
}

#[async_trait]
impl OwnershipStore for InMemoryOwnershipStore {
    async fn register(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        let mut owners = self.owners.write().unwrap();

        if let Some(existing) = owners.get(file_hash) {
            if existing != owner {
                return Err(AuthError::AlreadyExists(format!(
                    "File {file_hash} already owned by different key"
                )));
            }
            // Already registered to same owner — idempotent
            return Ok(());
        }

        owners.insert(*file_hash, *owner);
        Ok(())
    }

    async fn is_owner(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<bool> {
        let owners = self.owners.read().unwrap();
        Ok(owners.get(file_hash) == Some(owner))
    }

    async fn list_owned(&self, owner: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>> {
        let owners = self.owners.read().unwrap();
        Ok(owners
            .iter()
            .filter(|(_, o)| *o == owner)
            .map(|(h, _)| *h)
            .collect())
    }

    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        let mut owners = self.owners.write().unwrap();

        match owners.get(file_hash) {
            Some(current) if current == from => {
                owners.insert(*file_hash, *to);
                Ok(())
            }
            Some(_) => Err(AuthError::NotAuthorized("Only owner can transfer".into())),
            None => Err(AuthError::FileNotFound(file_hash.to_string())),
        }
    }

    async fn grant_access(&self, grant: AccessGrant) -> AuthResult<()> {
        // Verify the granter owns the file
        let owners = self.owners.read().unwrap();
        match owners.get(&grant.file_hash) {
            Some(owner) if *owner == grant.owner => {}
            Some(_) => {
                return Err(AuthError::NotAuthorized(
                    "Only owner can grant access".into(),
                ));
            }
            None => return Err(AuthError::FileNotFound(grant.file_hash.to_string())),
        }
        drop(owners);

        let key = (grant.file_hash, grant.grantee);
        self.grants.write().unwrap().insert(key, grant);
        Ok(())
    }

    async fn revoke_access(
        &self,
        owner: &PublicKeyFingerprint,
        grantee: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        // Verify ownership
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can revoke".into()));
        }

        let key = (*file_hash, *grantee);
        self.grants.write().unwrap().remove(&key);
        Ok(())
    }

    async fn has_access(
        &self,
        pubkey: &PublicKeyFingerprint,
        file_hash: &Hash,
        operation: Operation,
    ) -> AuthResult<bool> {
        // Owner has all access
        if self.is_owner(pubkey, file_hash).await? {
            return Ok(true);
        }

        // Check grants
        let grants = self.grants.read().unwrap();
        let key = (*file_hash, *pubkey);

        match grants.get(&key) {
            Some(grant) => {
                if grant.is_expired() {
                    Ok(false)
                } else {
                    Ok(grant.permits(operation))
                }
            }
            None => Ok(false),
        }
    }

    async fn list_grants(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<Vec<AccessGrant>> {
        // Verify ownership
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized(
                "Only owner can list grants".into(),
            ));
        }

        let grants = self.grants.read().unwrap();
        Ok(grants
            .iter()
            .filter(|((h, _), _)| h == file_hash)
            .map(|(_, g)| g.clone())
            .collect())
    }

    async fn list_shared_with(&self, grantee: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>> {
        let grants = self.grants.read().unwrap();
        let mut files: HashSet<Hash> = HashSet::new();

        for ((file_hash, g), grant) in grants.iter() {
            if g == grantee && !grant.is_expired() {
                files.insert(*file_hash);
            }
        }

        Ok(files.into_iter().collect())
    }

    async fn unregister(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        // Verify ownership
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can unregister".into()));
        }

        // Remove ownership
        self.owners.write().unwrap().remove(file_hash);

        // Remove all grants for this file
        let mut grants = self.grants.write().unwrap();
        grants.retain(|(h, _), _| h != file_hash);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn test_register_and_ownership() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        assert!(store.is_owner(&owner, &file).await.unwrap());
        assert!(!store.is_owner(&fp(2), &file).await.unwrap());
    }

    #[tokio::test]
    async fn test_register_idempotent() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();
        store.register(&owner, &file).await.unwrap(); // Should succeed
    }

    #[tokio::test]
    async fn test_register_conflict() {
        let store = InMemoryOwnershipStore::new();
        let file = blake3::hash(b"test");

        store.register(&fp(1), &file).await.unwrap();
        let result = store.register(&fp(2), &file).await;

        assert!(matches!(result, Err(AuthError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_grant_access() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let grantee = fp(2);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        let grant = AccessGrant::new(file, owner, grantee, vec![Operation::Read], None);
        store.grant_access(grant).await.unwrap();

        assert!(
            store
                .has_access(&grantee, &file, Operation::Read)
                .await
                .unwrap()
        );
        assert!(
            !store
                .has_access(&grantee, &file, Operation::Write)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_revoke_access() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let grantee = fp(2);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        let grant = AccessGrant::new(file, owner, grantee, vec![Operation::Read], None);
        store.grant_access(grant).await.unwrap();

        assert!(
            store
                .has_access(&grantee, &file, Operation::Read)
                .await
                .unwrap()
        );

        store.revoke_access(&owner, &grantee, &file).await.unwrap();

        assert!(
            !store
                .has_access(&grantee, &file, Operation::Read)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_transfer_ownership() {
        let store = InMemoryOwnershipStore::new();
        let alice = fp(1);
        let bob = fp(2);
        let file = blake3::hash(b"test");

        store.register(&alice, &file).await.unwrap();
        store.transfer(&alice, &bob, &file).await.unwrap();

        assert!(!store.is_owner(&alice, &file).await.unwrap());
        assert!(store.is_owner(&bob, &file).await.unwrap());
    }

    #[tokio::test]
    async fn test_owner_has_all_access() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        use crate::capability::ALL_OPERATIONS;
        for op in ALL_OPERATIONS {
            assert!(store.has_access(&owner, &file, *op).await.unwrap());
        }
    }
}
