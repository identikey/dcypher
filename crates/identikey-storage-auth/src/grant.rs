//! Access grants: records of delegated access

use crate::capability::Operation;
use crate::fingerprint::PublicKeyFingerprint;

/// A record of access granted from owner to grantee
#[derive(Clone, Debug)]
pub struct AccessGrant {
    /// File being shared
    pub file_hash: blake3::Hash,
    /// Who owns the file
    pub owner: PublicKeyFingerprint,
    /// Who has been granted access
    pub grantee: PublicKeyFingerprint,
    /// What operations are permitted
    pub operations: Vec<Operation>,
    /// When the grant expires (0 = never)
    pub expires_at: u64,
    /// When the grant was created (Unix timestamp)
    pub created_at: u64,
}

impl AccessGrant {
    pub fn new(
        file_hash: blake3::Hash,
        owner: PublicKeyFingerprint,
        grantee: PublicKeyFingerprint,
        operations: Vec<Operation>,
        expires_at: Option<u64>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            file_hash,
            owner,
            grantee,
            operations,
            expires_at: expires_at.unwrap_or(0),
            created_at: now,
        }
    }

    /// Check if the grant has expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > self.expires_at
    }

    /// Check if a specific operation is permitted
    pub fn permits(&self, op: Operation) -> bool {
        self.operations.contains(&op)
    }
}
