//! ED25519 classical signatures via ed25519-dalek

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::FfiError;

/// An ED25519 keypair
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Generate a new ED25519 keypair
pub fn ed25519_keygen() -> Ed25519KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ed25519KeyPair {
        signing_key,
        verifying_key,
    }
}

/// Sign a message with an ED25519 secret key
pub fn ed25519_sign(sk: &SigningKey, message: &[u8]) -> Signature {
    sk.sign(message)
}

/// Verify an ED25519 signature
pub fn ed25519_verify(
    pk: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), FfiError> {
    pk.verify(message, signature)
        .map_err(|_| FfiError::Ed25519Verification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_roundtrip() {
        let kp = ed25519_keygen();
        let message = b"Hello ED25519";
        let sig = ed25519_sign(&kp.signing_key, message);
        assert!(ed25519_verify(&kp.verifying_key, message, &sig).is_ok());
    }

    #[test]
    fn test_ed25519_tampered_message() {
        let kp = ed25519_keygen();
        let message = b"Hello ED25519";
        let sig = ed25519_sign(&kp.signing_key, message);

        let mut bad_message = message.to_vec();
        bad_message[0] ^= 0xFF;

        assert!(ed25519_verify(&kp.verifying_key, &bad_message, &sig).is_err());
    }

    #[test]
    fn test_ed25519_wrong_key() {
        let kp1 = ed25519_keygen();
        let kp2 = ed25519_keygen();
        let message = b"Hello ED25519";
        let sig = ed25519_sign(&kp1.signing_key, message);

        assert!(ed25519_verify(&kp2.verifying_key, message, &sig).is_err());
    }
}
