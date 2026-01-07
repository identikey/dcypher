//! Chunking utilities for large file storage
//!
//! Splits files into content-addressed chunks for efficient storage/transfer.
//! Default chunk size: 4 MiB (aligned with typical S3 multipart size).

use blake3::Hash;

/// Default chunk size: 4 MiB
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// A chunk with its hash and data
#[derive(Clone, Debug)]
pub struct Chunk {
    pub hash: Hash,
    pub data: Vec<u8>,
    pub index: usize,
}

/// Manifest for a chunked file
#[derive(Clone, Debug)]
pub struct ChunkManifest {
    /// Hash algorithm identifier (for future agility)
    pub hash_algorithm: &'static str,
    /// Blake3 hash of the complete data
    pub file_hash: Hash,
    /// Total size of original data
    pub total_size: u64,
    /// Ordered list of chunk hashes
    pub chunk_hashes: Vec<Hash>,
    /// Chunk size used (for reconstruction)
    pub chunk_size: usize,
}

/// Current hash algorithm identifier
pub const HASH_ALGORITHM: &str = "blake3";

/// Split data into chunks
///
/// Each chunk is hashed independently. Returns manifest + chunks.
pub fn split(data: &[u8], chunk_size: usize) -> (ChunkManifest, Vec<Chunk>) {
    let file_hash = blake3::hash(data);
    let mut chunks = Vec::new();
    let mut chunk_hashes = Vec::new();

    for (i, chunk_data) in data.chunks(chunk_size).enumerate() {
        let hash = blake3::hash(chunk_data);
        chunk_hashes.push(hash);
        chunks.push(Chunk {
            hash,
            data: chunk_data.to_vec(),
            index: i,
        });
    }

    let manifest = ChunkManifest {
        hash_algorithm: HASH_ALGORITHM,
        file_hash,
        total_size: data.len() as u64,
        chunk_hashes,
        chunk_size,
    };

    (manifest, chunks)
}

/// Split with default chunk size (4 MiB)
pub fn split_default(data: &[u8]) -> (ChunkManifest, Vec<Chunk>) {
    split(data, DEFAULT_CHUNK_SIZE)
}

/// Reassemble chunks into original data
///
/// Chunks must be provided in order. Verifies:
/// 1. Each chunk matches its expected hash
/// 2. Final reassembled data matches file_hash
///
/// Returns `None` if verification fails.
pub fn join(manifest: &ChunkManifest, chunks: &[&[u8]]) -> Option<Vec<u8>> {
    if chunks.len() != manifest.chunk_hashes.len() {
        return None;
    }

    // Verify each chunk
    for (chunk, expected_hash) in chunks.iter().zip(&manifest.chunk_hashes) {
        if blake3::hash(chunk) != *expected_hash {
            return None;
        }
    }

    // Reassemble
    let mut data = Vec::with_capacity(manifest.total_size as usize);
    for chunk in chunks {
        data.extend_from_slice(chunk);
    }

    // Verify final hash
    if blake3::hash(&data) != manifest.file_hash {
        return None;
    }

    Some(data)
}

/// Store a file as chunks
pub async fn store_chunked<S: crate::ChunkStorage>(
    storage: &S,
    data: &[u8],
    chunk_size: usize,
) -> crate::StorageResult<ChunkManifest> {
    let (manifest, chunks) = split(data, chunk_size);

    for chunk in chunks {
        storage.put(&chunk.hash, &chunk.data).await?;
    }

    Ok(manifest)
}

/// Retrieve and reassemble a chunked file
pub async fn retrieve_chunked<S: crate::ChunkStorage>(
    storage: &S,
    manifest: &ChunkManifest,
) -> crate::StorageResult<Vec<u8>> {
    let mut chunk_data = Vec::with_capacity(manifest.chunk_hashes.len());

    for hash in &manifest.chunk_hashes {
        let data = storage.get(hash).await?;
        chunk_data.push(data);
    }

    let refs: Vec<&[u8]> = chunk_data.iter().map(|v| v.as_slice()).collect();
    join(manifest, &refs).ok_or_else(|| crate::StorageError::HashMismatch {
        expected: crate::hash_to_base58(&manifest.file_hash),
        actual: "verification failed".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_join_small() {
        let data = b"Small file that fits in one chunk";
        let (manifest, chunks) = split(data, 1024);

        assert_eq!(chunks.len(), 1);
        assert_eq!(manifest.chunk_hashes.len(), 1);

        let refs: Vec<&[u8]> = chunks.iter().map(|c| c.data.as_slice()).collect();
        let reassembled = join(&manifest, &refs).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_split_join_multiple_chunks() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let chunk_size = 1000;

        let (manifest, chunks) = split(&data, chunk_size);

        assert_eq!(chunks.len(), 10);
        assert_eq!(manifest.total_size, 10000);

        let refs: Vec<&[u8]> = chunks.iter().map(|c| c.data.as_slice()).collect();
        let reassembled = join(&manifest, &refs).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_join_wrong_chunk_fails() {
        let data = b"Original data";
        let (manifest, _) = split(data, 1024);

        let wrong_chunk = b"Wrong data";
        let result = join(&manifest, &[wrong_chunk.as_slice()]);
        assert!(result.is_none());
    }

    #[test]
    fn test_deduplication() {
        // Identical chunks should have identical hashes
        let data = vec![0u8; 2048];
        let (manifest, chunks) = split(&data, 1024);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].hash, chunks[1].hash);
        assert_eq!(manifest.chunk_hashes[0], manifest.chunk_hashes[1]);
    }

    #[tokio::test]
    async fn test_store_retrieve_chunked() {
        use crate::InMemoryStorage;

        let storage = InMemoryStorage::new();
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let manifest = store_chunked(&storage, &data, 1000).await.unwrap();
        assert_eq!(manifest.chunk_hashes.len(), 5);

        let retrieved = retrieve_chunked(&storage, &manifest).await.unwrap();
        assert_eq!(retrieved, data);
    }
}
