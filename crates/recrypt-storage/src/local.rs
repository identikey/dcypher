//! Local filesystem storage backend

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use blake3::Hash;
use tokio::fs;

use crate::error::{StorageError, StorageResult};
use crate::traits::{ChunkStorage, hash_from_base58, hash_to_base58};

/// Algorithm prefix for Blake3 hashes (enables future hash agility)
const HASH_ALG_PREFIX: &str = "b3";

/// Local filesystem storage
///
/// Stores chunks as files named by their base58 hash with algorithm prefix.
/// Structure: `{root}/chunks/b3/{hash_base58}`
pub struct LocalFileStorage {
    root: PathBuf,
}

impl LocalFileStorage {
    /// Create storage at the given root directory
    ///
    /// Creates the directory structure if it doesn't exist.
    pub async fn new(root: impl AsRef<Path>) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();
        let chunks_dir = root.join("chunks").join(HASH_ALG_PREFIX);
        fs::create_dir_all(&chunks_dir).await?;
        Ok(Self { root })
    }

    fn chunk_path(&self, hash: &Hash) -> PathBuf {
        self.root
            .join("chunks")
            .join(HASH_ALG_PREFIX)
            .join(hash_to_base58(hash))
    }
}

#[async_trait]
impl ChunkStorage for LocalFileStorage {
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()> {
        let computed = blake3::hash(data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        let path = self.chunk_path(hash);
        fs::write(&path, data).await?;
        Ok(())
    }

    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>> {
        let path = self.chunk_path(hash);
        match fs::read(&path).await {
            Ok(data) => {
                // Verify on read (defense in depth)
                let computed = blake3::hash(&data);
                if computed != *hash {
                    return Err(StorageError::HashMismatch {
                        expected: hash_to_base58(hash),
                        actual: hash_to_base58(&computed),
                    });
                }
                Ok(data)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(hash_to_base58(hash)))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn exists(&self, hash: &Hash) -> StorageResult<bool> {
        let path = self.chunk_path(hash);
        Ok(path.exists())
    }

    async fn delete(&self, hash: &Hash) -> StorageResult<()> {
        let path = self.chunk_path(hash);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(&self) -> StorageResult<Vec<Hash>> {
        let chunks_dir = self.root.join("chunks").join(HASH_ALG_PREFIX);
        let mut hashes = Vec::new();

        let mut entries = fs::read_dir(&chunks_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                if let Some(hash) = hash_from_base58(name) {
                    hashes.push(hash);
                }
            }
        }

        Ok(hashes)
    }
}
