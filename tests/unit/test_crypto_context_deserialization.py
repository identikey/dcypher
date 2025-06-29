"""
Tests for OpenFHE CryptoContext deserialization behavior and context singleton solutions.

This file documents critical OpenFHE behaviors that affect proxy re-encryption
in distributed systems, and demonstrates how the context singleton pattern
can resolve these limitations.
"""

import pytest
from lib import pre
from src.crypto.context_manager import CryptoContextManager


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

    def test_same_context_instance_required_for_operations_limitation(
        self, serialized_context_bytes
    ):
        """Test that OpenFHE requires the same context instance for all operations.

        This test documents the critical limitation that affects our proxy re-encryption system.
        This test is expected to fail and documents the limitation.
        """
        # Create two different context instances from the same bytes
        alice_cc = pre.deserialize_cc(serialized_context_bytes)
        bob_cc = pre.deserialize_cc(serialized_context_bytes)

        # Try to generate keys with different context instances
        # This should fail with "Cannot find context for the given pointer"
        with pytest.raises(
            RuntimeError, match="Cannot find context for the given pointer"
        ):
            alice_keys = pre.generate_keys(alice_cc)
            bob_keys = pre.generate_keys(bob_cc)

    def test_context_singleton_resolves_instance_requirement(self, base_crypto_context):
        """Test that the context singleton pattern resolves the instance requirement."""
        # Reset the singleton to start fresh
        CryptoContextManager.reset_all_instances()
        context_manager = CryptoContextManager()

        # Set the context in the singleton
        context_manager._context = base_crypto_context
        context_manager._context_params = {
            "scheme": "BFV",
            "plaintext_modulus": 65537,
            "multiplicative_depth": 2,
            "scaling_mod_size": 50,
            "batch_size": 8,
        }

        # All operations use the SAME context instance from the singleton
        shared_cc = context_manager.get_context()

        # Generate keys for Alice and Bob using the same context instance
        alice_keys = pre.generate_keys(shared_cc)
        bob_keys = pre.generate_keys(shared_cc)

        # Generate re-encryption key - this should work because all objects
        # were created with the same context instance
        re_key = pre.generate_re_encryption_key(
            shared_cc, alice_keys.secretKey, bob_keys.publicKey
        )

        # Test full workflow
        test_data = b"test data for singleton pattern"
        slot_count = pre.get_slot_count(shared_cc)
        coeffs = pre.bytes_to_coefficients(test_data, slot_count)

        # Encrypt with Alice's key
        alice_ciphertext = pre.encrypt(shared_cc, alice_keys.publicKey, coeffs)

        # Re-encrypt for Bob
        bob_ciphertexts = pre.re_encrypt(shared_cc, re_key, alice_ciphertext)

        # Decrypt with Bob's key
        decrypted_coeffs = pre.decrypt(
            shared_cc, bob_keys.secretKey, bob_ciphertexts, len(coeffs)
        )
        decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(test_data))

        assert decrypted_data == test_data
        print("✅ Context singleton pattern enables full PRE workflow!")

        # Clean up
        context_manager.reset()


class TestDocumentedLimitations:
    """Document the fundamental limitations and their solutions."""

    def test_limitation_context_instance_binding_documented(
        self, serialized_context_bytes
    ):
        """Document: All crypto objects are bound to their creating context instance.

        This test documents the limitation and is expected to fail.
        """
        # Try to create multiple context instances - this should fail
        with pytest.raises(
            RuntimeError, match="Cannot find context for the given pointer"
        ):
            cc1 = pre.deserialize_cc(serialized_context_bytes)
            cc2 = pre.deserialize_cc(serialized_context_bytes)

            keys1 = pre.generate_keys(cc1)
            keys2 = pre.generate_keys(cc2)

    def test_solution_context_singleton_pattern(self, base_crypto_context):
        """Demonstrate: Context singleton pattern resolves the limitation."""
        # Reset the singleton
        CryptoContextManager.reset_all_instances()
        context_manager = CryptoContextManager()

        # Initialize with the base context
        context_manager._context = base_crypto_context

        # All operations use the same context instance
        shared_cc = context_manager.get_context()

        # Multiple key generations work because they use the same context
        keys1 = pre.generate_keys(shared_cc)
        keys2 = pre.generate_keys(shared_cc)

        # Re-encryption key generation works
        re_key = pre.generate_re_encryption_key(
            shared_cc, keys1.secretKey, keys2.publicKey
        )

        assert re_key is not None
        print("✅ Context singleton pattern resolves OpenFHE limitations!")

        # Clean up
        context_manager.reset()


class TestContextSingletonIntegration:
    """Test the context singleton integration with our system."""

    def test_singleton_serialization_deserialization_workflow(
        self, base_crypto_context
    ):
        """Test the complete singleton serialization/deserialization workflow."""
        # Reset singleton
        CryptoContextManager.reset_all_instances()
        server_context_manager = CryptoContextManager()

        # Server initializes context
        server_context_manager._context = base_crypto_context

        # Server serializes context for clients
        serialized_context = server_context_manager.serialize_context()

        # Client gets context from server
        CryptoContextManager.reset_all_instances()  # Simulate different client process
        client_context_manager = CryptoContextManager()

        # Client deserializes the server's context
        client_cc = client_context_manager.deserialize_context(serialized_context)

        # Verify client context works
        keys = pre.generate_keys(client_cc)
        assert keys.publicKey is not None
        assert keys.secretKey is not None

        # Verify serialization roundtrip
        client_serialized = client_context_manager.serialize_context()
        assert client_serialized == serialized_context

        print("✅ Context singleton supports client-server serialization workflow!")

        # Clean up
        server_context_manager.reset()
        client_context_manager.reset()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
