use super::BackendId;
use crate::error::{PreError, PreResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A PRE public key (backend-agnostic wrapper)
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) backend: BackendId,
    pub(crate) bytes: Vec<u8>,
}

impl PublicKey {
    pub fn new(backend: BackendId, bytes: Vec<u8>) -> Self {
        Self { backend, bytes }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Serialize with backend tag
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8];
        out.extend(&self.bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> PreResult<Self> {
        if bytes.is_empty() {
            return Err(PreError::InvalidKey("Empty public key".into()));
        }
        let backend = BackendId::try_from(bytes[0])?;
        Ok(Self {
            backend,
            bytes: bytes[1..].to_vec(),
        })
    }
}

/// A PRE secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    pub(crate) backend: BackendId,
    #[zeroize(skip)]
    _backend_skip: (), // Backend ID doesn't need zeroizing
    pub(crate) bytes: Vec<u8>,
}

impl SecretKey {
    pub fn new(backend: BackendId, bytes: Vec<u8>) -> Self {
        Self {
            backend,
            _backend_skip: (),
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A keypair (public + secret)
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// A recryption key (transforms ciphertexts from one recipient to another)
#[derive(Clone)]
pub struct RecryptKey {
    pub(crate) backend: BackendId,
    pub(crate) from_public: PublicKey,
    pub(crate) to_public: PublicKey,
    #[allow(dead_code)] // Used in Phase 2.3+
    pub(crate) bytes: Vec<u8>,
}

impl RecryptKey {
    pub fn new(
        backend: BackendId,
        from_public: PublicKey,
        to_public: PublicKey,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            backend,
            from_public,
            to_public,
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn from_public(&self) -> &PublicKey {
        &self.from_public
    }

    pub fn to_public(&self) -> &PublicKey {
        &self.to_public
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Serialize with backend tag and public keys
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8];
        // Include from_public
        out.extend(self.from_public.to_bytes());
        // Include to_public
        out.extend(self.to_public.to_bytes());
        // Include recrypt key bytes
        out.extend(&self.bytes);
        out
    }
}

/// A PRE ciphertext
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub(crate) backend: BackendId,
    pub(crate) level: u8, // 0 = original, 1+ = recrypted
    pub(crate) bytes: Vec<u8>,
}

impl Ciphertext {
    pub fn new(backend: BackendId, level: u8, bytes: Vec<u8>) -> Self {
        Self {
            backend,
            level,
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8, self.level];
        out.extend(&self.bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> PreResult<Self> {
        if bytes.len() < 2 {
            return Err(PreError::Deserialization("Ciphertext too short".into()));
        }
        let backend = BackendId::try_from(bytes[0])?;
        Ok(Self {
            backend,
            level: bytes[1],
            bytes: bytes[2..].to_vec(),
        })
    }
}
