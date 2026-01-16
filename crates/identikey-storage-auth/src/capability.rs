//! Capability: signed, time-limited access token

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use recrypt_core::sign::{MultiSig, SigningKeys, VerifyingKeys, sign_message, verify_message};

/// Operations that can be granted via capability
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Read file content
    Read,
    /// Write/update file (re-upload)
    Write,
    /// Delete file
    Delete,
    /// Share file with others (issue sub-capabilities)
    Share,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Delete => "delete",
            Operation::Share => "share",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read" => Some(Operation::Read),
            "write" => Some(Operation::Write),
            "delete" => Some(Operation::Delete),
            "share" => Some(Operation::Share),
            _ => None,
        }
    }
}

/// All operations for convenience
#[allow(dead_code)]
pub const ALL_OPERATIONS: &[Operation] = &[
    Operation::Read,
    Operation::Write,
    Operation::Delete,
    Operation::Share,
];

/// A capability granting access to a file
///
/// Capabilities are signed by the issuer and can be verified by anyone
/// with the issuer's public key.
#[derive(Clone, Debug)]
pub struct Capability {
    /// Format version
    pub version: u32,
    /// Content address of the file
    pub file_hash: blake3::Hash,
    /// Who this capability is granted to
    pub granted_to: PublicKeyFingerprint,
    /// Permitted operations
    pub operations: Vec<Operation>,
    /// Expiration timestamp (Unix seconds, 0 = no expiry)
    pub expires_at: u64,
    /// Who issued this capability
    pub issuer: PublicKeyFingerprint,
    /// Signature over capability fields (None if unsigned)
    pub signature: Option<MultiSig>,
}

impl Capability {
    /// Current capability format version
    pub const VERSION: u32 = 1;

    /// Create a new unsigned capability
    pub fn new(
        file_hash: blake3::Hash,
        granted_to: PublicKeyFingerprint,
        operations: Vec<Operation>,
        expires_at: Option<u64>,
        issuer: PublicKeyFingerprint,
    ) -> Self {
        Self {
            version: Self::VERSION,
            file_hash,
            granted_to,
            operations,
            expires_at: expires_at.unwrap_or(0),
            issuer,
            signature: None,
        }
    }

    /// Compute the bytes to be signed
    fn signature_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Version (4 bytes)
        payload.extend(self.version.to_le_bytes());

        // File hash (32 bytes)
        payload.extend(self.file_hash.as_bytes());

        // Granted to (32 bytes)
        payload.extend(self.granted_to.as_bytes());

        // Operations (variable, but deterministic)
        let mut ops: Vec<_> = self.operations.iter().map(|o| o.as_str()).collect();
        ops.sort(); // Canonical order
        for op in ops {
            payload.extend(op.as_bytes());
            payload.push(0); // Separator
        }

        // Expires at (8 bytes)
        payload.extend(self.expires_at.to_le_bytes());

        // Issuer (32 bytes)
        payload.extend(self.issuer.as_bytes());

        payload
    }

    /// Sign the capability
    pub fn sign(&mut self, keys: &SigningKeys) -> AuthResult<()> {
        let payload = self.signature_payload();
        self.signature = Some(sign_message(&payload, keys)?);
        Ok(())
    }

    /// Create a signed capability in one step
    pub fn new_signed(
        file_hash: blake3::Hash,
        granted_to: PublicKeyFingerprint,
        operations: Vec<Operation>,
        expires_at: Option<u64>,
        issuer: PublicKeyFingerprint,
        keys: &SigningKeys,
    ) -> AuthResult<Self> {
        let mut cap = Self::new(file_hash, granted_to, operations, expires_at, issuer);
        cap.sign(keys)?;
        Ok(cap)
    }

    /// Verify the capability signature
    pub fn verify_signature(&self, issuer_keys: &VerifyingKeys) -> AuthResult<()> {
        let sig = self.signature.as_ref().ok_or(AuthError::InvalidSignature)?;

        let payload = self.signature_payload();
        verify_message(&payload, sig, issuer_keys)?;
        Ok(())
    }

    /// Check if capability has expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // No expiry
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

    /// Full verification: signature + expiry + operation
    pub fn verify(&self, issuer_keys: &VerifyingKeys, required_op: Operation) -> AuthResult<()> {
        // Check signature
        self.verify_signature(issuer_keys)?;

        // Check expiry
        if self.is_expired() {
            return Err(AuthError::CapabilityExpired);
        }

        // Check operation
        if !self.permits(required_op) {
            return Err(AuthError::OperationNotPermitted(
                required_op.as_str().into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recrypt_ffi::ed25519::ed25519_keygen;
    use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};

    fn test_keys() -> (SigningKeys, VerifyingKeys) {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let signing = SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: pq_kp.secret_key.clone(),
        };

        let verifying = VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: pq_kp.public_key.clone(),
        };

        (signing, verifying)
    }

    #[test]
    fn test_capability_sign_verify() {
        let (signing, verifying) = test_keys();

        let file_hash = blake3::hash(b"test file");
        let grantee = PublicKeyFingerprint::from_bytes([1u8; 32]);
        let issuer = PublicKeyFingerprint::from_bytes([2u8; 32]);

        let cap = Capability::new_signed(
            file_hash,
            grantee,
            vec![Operation::Read],
            None,
            issuer,
            &signing,
        )
        .unwrap();

        assert!(cap.verify_signature(&verifying).is_ok());
    }

    #[test]
    fn test_capability_expiry() {
        let file_hash = blake3::hash(b"test");
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);

        // No expiry
        let cap = Capability::new(file_hash, fp, vec![Operation::Read], None, fp);
        assert!(!cap.is_expired());

        // Expired
        let cap = Capability::new(file_hash, fp, vec![Operation::Read], Some(1), fp);
        assert!(cap.is_expired());

        // Future expiry
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let cap = Capability::new(file_hash, fp, vec![Operation::Read], Some(future), fp);
        assert!(!cap.is_expired());
    }

    #[test]
    fn test_capability_operations() {
        let file_hash = blake3::hash(b"test");
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);

        let cap = Capability::new(
            file_hash,
            fp,
            vec![Operation::Read, Operation::Write],
            None,
            fp,
        );

        assert!(cap.permits(Operation::Read));
        assert!(cap.permits(Operation::Write));
        assert!(!cap.permits(Operation::Delete));
        assert!(!cap.permits(Operation::Share));
    }
}
