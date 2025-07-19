"""
Basic test for dual classical key support (ECDSA + ED25519) without PRE dependencies.
"""

from dcypher.lib.key_manager import KeyManager
from dcypher.lib.auth import (
    generate_ed25519_keypair,
    verify_dual_classical_signatures,
    sign_message_with_keys,
    ed25519_public_key_to_hex,
)


def test_ed25519_key_generation():
    """Test that ED25519 key generation works correctly."""
    private_key, public_key_hex = generate_ed25519_keypair()

    assert private_key is not None
    assert len(public_key_hex) == 64  # 32 bytes = 64 hex chars

    # Test signing and verification
    message = b"test message"
    signature = private_key.sign(message)

    # Verify directly
    private_key.public_key().verify(signature, message)
    print("✅ ED25519 key generation test passed")


def test_dual_classical_signature_verification():
    """Test that dual classical signature verification works."""
    # Generate ECDSA key
    import ecdsa

    ecdsa_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    ecdsa_vk = ecdsa_sk.get_verifying_key()
    assert ecdsa_vk is not None, "ECDSA verifying key should not be None"
    ecdsa_pk_hex = ecdsa_vk.to_string("uncompressed").hex()

    # Generate ED25519 key
    ed25519_sk, ed25519_pk_hex = generate_ed25519_keypair()

    # Test message
    message = b"test dual signature message"

    # Sign with ECDSA
    import hashlib

    ecdsa_signature = ecdsa_sk.sign(message, hashfunc=hashlib.sha256)
    ecdsa_sig_hex = ecdsa_signature.hex()

    # Sign with ED25519
    ed25519_signature = ed25519_sk.sign(message)
    ed25519_sig_hex = ed25519_signature.hex()

    # Verify dual signatures
    is_valid = verify_dual_classical_signatures(
        ecdsa_pk_hex=ecdsa_pk_hex,
        ecdsa_sig_hex=ecdsa_sig_hex,
        ed25519_pk_hex=ed25519_pk_hex,
        ed25519_sig_hex=ed25519_sig_hex,
        message=message,
    )

    assert is_valid
    print("✅ Dual classical signature verification test passed")


def test_key_manager_dual_key_generation():
    """Test that KeyManager can generate both types of classical keys."""
    # Test ECDSA key generation
    sk_classic, pk_classic_hex = KeyManager.generate_classic_keypair()
    assert len(pk_classic_hex) == 130  # Uncompressed ECDSA public key

    # Test ED25519 key generation
    sk_ed25519, pk_ed25519_hex = KeyManager.generate_ed25519_keypair()
    assert len(pk_ed25519_hex) == 64  # ED25519 public key

    print("✅ KeyManager dual key generation test passed")


def test_dual_classical_signing_with_keys():
    """Test that sign_message_with_keys works with dual classical keys."""
    # Create manually generated keys to avoid crypto context issues
    sk_classic, pk_classic_hex = KeyManager.generate_classic_keypair()
    sk_ed25519, pk_ed25519_hex = KeyManager.generate_ed25519_keypair()

    # Create minimal PQ key for testing
    pq_pk, pq_sk = KeyManager.generate_pq_keypair("ML-DSA-87")

    keys_data = {
        "classic_sk": sk_classic,
        "ed25519_sk": sk_ed25519,
        "pq_keys": [{"sk": pq_sk, "pk_hex": pq_pk.hex(), "alg": "ML-DSA-87"}],
    }

    # Test signing
    message = b"test message for dual signing"
    signatures = sign_message_with_keys(message, keys_data)

    assert "classic_signature" in signatures
    assert "ed25519_signature" in signatures
    assert "pq_signatures" in signatures

    # Verify the signatures work
    is_valid = verify_dual_classical_signatures(
        ecdsa_pk_hex=pk_classic_hex,
        ecdsa_sig_hex=signatures["classic_signature"],
        ed25519_pk_hex=pk_ed25519_hex,
        ed25519_sig_hex=signatures["ed25519_signature"],
        message=message,
    )

    assert is_valid
    print("✅ Dual classical signing test passed")


if __name__ == "__main__":
    # Run all tests
    test_ed25519_key_generation()
    test_dual_classical_signature_verification()
    test_key_manager_dual_key_generation()
    test_dual_classical_signing_with_keys()
    print("\n🎉 All basic dual classical key tests passed!")
