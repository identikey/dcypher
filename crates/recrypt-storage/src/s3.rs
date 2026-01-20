//! S3-compatible storage backend (Minio, AWS S3, Backblaze, etc.)

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use blake3::Hash;

use crate::error::{StorageError, StorageResult};
use crate::traits::{ChunkStorage, hash_from_base58, hash_to_base58};

/// Algorithm prefix for Blake3 hashes (enables future hash agility)
const HASH_ALG_PREFIX: &str = "b3";

/// S3-compatible storage
///
/// Bucket structure:
/// ```text
/// {bucket}/
///   chunks/b3/{hash_base58}
/// ```
pub struct S3Storage {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Storage {
    /// Create from existing AWS SDK client
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            prefix: "chunks".into(),
        }
    }

    /// Create with custom prefix (for namespacing)
    pub fn with_prefix(
        client: Client,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            prefix: prefix.into(),
        }
    }

    /// Create configured for local Minio
    ///
    /// Expects environment variables:
    /// - `MINIO_ENDPOINT` (default: http://localhost:9000)
    /// - `MINIO_ACCESS_KEY` (default: minioadmin)
    /// - `MINIO_SECRET_KEY` (default: minioadmin)
    pub async fn minio(bucket: impl Into<String>) -> StorageResult<Self> {
        let endpoint =
            std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into());
        let access_key = std::env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".into());
        let secret_key = std::env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "minioadmin".into());

        let creds =
            aws_sdk_s3::config::Credentials::new(access_key, secret_key, None, None, "minio");

        let config = aws_sdk_s3::Config::builder()
            .endpoint_url(endpoint)
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(creds)
            .force_path_style(true) // Required for Minio
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .build();

        let client = Client::from_conf(config);
        Ok(Self::new(client, bucket))
    }

    /// Ensure bucket exists (call on startup)
    pub async fn ensure_bucket(&self) -> StorageResult<()> {
        // Try to create bucket - S3/Minio returns success if it already exists
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // Check if bucket already exists by trying head_bucket
                match self.client.head_bucket().bucket(&self.bucket).send().await {
                    Ok(_) => Ok(()), // Bucket exists, we're good
                    Err(_) => Err(StorageError::Backend(format!(
                        "Failed to create or access bucket: {e}"
                    ))),
                }
            }
        }
    }

    fn object_key(&self, hash: &Hash) -> String {
        format!(
            "{}/{}/{}",
            self.prefix,
            HASH_ALG_PREFIX,
            hash_to_base58(hash)
        )
    }
}

#[async_trait]
impl ChunkStorage for S3Storage {
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()> {
        // Verify hash before upload
        let computed = blake3::hash(data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        let key = self.object_key(hash);
        let body = ByteStream::from(data.to_vec());

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("S3 PUT failed: {e}")))?;

        Ok(())
    }

    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>> {
        let key = self.object_key(hash);

        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                if is_not_found(&e) {
                    StorageError::NotFound(hash_to_base58(hash))
                } else {
                    StorageError::Backend(format!("S3 GET failed: {e}"))
                }
            })?;

        let data = response
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to read body: {e}")))?
            .into_bytes()
            .to_vec();

        // Verify on read
        let computed = blake3::hash(&data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        Ok(data)
    }

    async fn exists(&self, hash: &Hash) -> StorageResult<bool> {
        let key = self.object_key(hash);

        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(StorageError::Backend(format!("S3 HEAD failed: {e}"))),
        }
    }

    async fn delete(&self, hash: &Hash) -> StorageResult<()> {
        let key = self.object_key(hash);

        // S3 delete is already idempotent
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("S3 DELETE failed: {e}")))?;

        Ok(())
    }

    async fn list(&self) -> StorageResult<Vec<Hash>> {
        let mut hashes = Vec::new();
        let mut continuation_token: Option<String> = None;
        let full_prefix = format!("{}/{}/", self.prefix, HASH_ALG_PREFIX);

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full_prefix);

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| StorageError::Backend(format!("S3 LIST failed: {e}")))?;

            if let Some(contents) = response.contents {
                for obj in contents {
                    if let Some(key) = obj.key {
                        // Extract hash from key: "chunks/b3/{hash_base58}"
                        if let Some(hash_b58) = key.strip_prefix(&full_prefix)
                            && let Some(hash) = hash_from_base58(hash_b58)
                        {
                            hashes.push(hash);
                        }
                    }
                }
            }

            match response.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        Ok(hashes)
    }
}

fn is_not_found<E>(err: &SdkError<E>) -> bool {
    matches!(err, SdkError::ServiceError(e) if e.raw().status().as_u16() == 404)
}
