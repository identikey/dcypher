"""
Tests for OpenFHE CryptoContext deserialization behavior and limitations.

This file documents critical OpenFHE behaviors that affect proxy re-encryption
in distributed systems. These tests serve as documentation for the limitations
we've discovered and the workarounds needed.
"""

import pytest
from lib import pre


@pytest.fixture
def base_crypto_context():
    """Create a base crypto context for testing serialization behavior."""
    cc = pre.create_crypto_context()
    pre.generate_keys(cc)  # Initialize the context
    return cc


@pytest.fixture
def serialized_context_bytes(base_crypto_context):
    """Provide serialized context bytes for deserialization tests."""
    return pre.serialize_to_bytes(base_crypto_context)


class TestCryptoContextDeserialization:
    """Test crypto context serialization and deserialization behavior."""

    def test_context_serialization_roundtrip_works(self, base_crypto_context):
        """Test that basic context serialization/deserialization works."""
        # Serialize the context
        cc_bytes = pre.serialize_to_bytes(base_crypto_context)

        # Deserialize it
        deserialized_cc = pre.deserialize_cc(cc_bytes)

        # Verify the deserialized context is functional
        slot_count = pre.get_slot_count(deserialized_cc)
        assert slot_count > 0

        # Test key generation works
        keys = pre.generate_keys(deserialized_cc)
        assert keys.publicKey is not None
        assert keys.secretKey is not None

        # Test encryption/decryption works
        test_data = b"test data"
        coeffs = pre.bytes_to_coefficients(test_data, slot_count)
        ciphertext = pre.encrypt(deserialized_cc, keys.publicKey, coeffs)
        decrypted_coeffs = pre.decrypt(
            deserialized_cc, keys.secretKey, ciphertext, len(coeffs)
        )
        decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(test_data))

        assert decrypted_data == test_data

    def test_multiple_deserializations_create_different_instances(
        self, serialized_context_bytes
    ):
        """Test that multiple deserializations create different context instances."""
        cc1 = pre.deserialize_cc(serialized_context_bytes)
        cc2 = pre.deserialize_cc(serialized_context_bytes)

        # They should be different object instances
        assert cc1 is not cc2

        # But both should be functional
        assert pre.get_slot_count(cc1) == pre.get_slot_count(cc2)

    def test_same_context_instance_required_for_operations(
        self, serialized_context_bytes
    ):
        """Test that OpenFHE requires the same context instance for all operations.

        This test documents the critical limitation that affects our proxy re-encryption system.
        """
        # Create two different context instances from the same bytes
        alice_cc = pre.deserialize_cc(serialized_context_bytes)
        bob_cc = pre.deserialize_cc(serialized_context_bytes)

        # Generate keys with different context instances
        alice_keys = pre.generate_keys(alice_cc)
        bob_keys = pre.generate_keys(bob_cc)

        # Try to generate a re-encryption key mixing keys from different contexts
        # This should fail with "Key was not generated with the same crypto context"
        with pytest.raises(
            RuntimeError, match="Key was not generated with the same crypto context"
        ):
            pre.generate_re_encryption_key(
                alice_cc, alice_keys.secretKey, bob_keys.publicKey
            )


class TestDocumentedLimitations:
    """Document the fundamental limitations we've discovered."""

    def test_limitation_context_instance_binding(self, serialized_context_bytes):
        """Document: All crypto objects are bound to their creating context instance."""
        cc1 = pre.deserialize_cc(serialized_context_bytes)
        cc2 = pre.deserialize_cc(serialized_context_bytes)

        keys1 = pre.generate_keys(cc1)
        keys2 = pre.generate_keys(cc2)

        # Keys are bound to their context instance
        with pytest.raises(RuntimeError):
            pre.generate_re_encryption_key(cc1, keys1.secretKey, keys2.publicKey)

        with pytest.raises(RuntimeError):
            pre.generate_re_encryption_key(cc2, keys1.secretKey, keys2.publicKey)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
