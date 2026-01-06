pub mod backends;
pub mod keys;
pub mod traits;

pub use keys::{Ciphertext, KeyPair, PublicKey, RecryptKey, SecretKey};
pub use traits::PreBackend;

use crate::error::PreError;

/// Identifies which backend produced a ciphertext/key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BackendId {
    /// OpenFHE BFV/PRE (post-quantum, lattice-based)
    Lattice = 0,
    /// IronCore recrypt (classical, BN254 pairing) - future
    EcPairing = 1,
    /// NuCypher Umbral (classical, secp256k1) - future
    EcSecp256k1 = 2,
    /// Mock backend for testing
    Mock = 255,
}

impl TryFrom<u8> for BackendId {
    type Error = PreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Lattice),
            1 => Ok(Self::EcPairing),
            2 => Ok(Self::EcSecp256k1),
            255 => Ok(Self::Mock),
            other => Err(PreError::InvalidKey(format!("Unknown backend ID: {other}"))),
        }
    }
}
