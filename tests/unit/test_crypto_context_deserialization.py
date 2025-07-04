"""
Tests for OpenFHE CryptoContext deserialization behavior.

This file documents critical OpenFHE behaviors that affect proxy re-encryption
in distributed systems.
"""

import pytest
from dcypher.lib import pre
from dcypher.crypto.context_manager import CryptoContextManager, OPENFHE_AVAILABLE


@pytest.fixture
def crypto_params():
    """Provides default crypto parameters for creating a context."""
    return {
        "scheme": "BFV",
        "plaintext_modulus": 65537,
        "multiplicative_depth": 2,
        "scaling_mod_size": 50,
        "batch_size": 8,
    }


@pytest.fixture
def base_crypto_context(crypto_params):
    """Create a base crypto context for testing serialization behavior."""
    with CryptoContextManager(**crypto_params) as manager:
        yield manager.get_context()


@pytest.fixture
def serialized_context(crypto_params):
    """Provide serialized context for deserialization tests."""
    with CryptoContextManager(**crypto_params) as manager:
        pre.generate_keys(manager.get_context())  # Initialize the context
        yield manager.serialize_context()


class TestCryptoContextDeserialization:
    """Test crypto context serialization and deserialization behavior."""

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_context_serialization_roundtrip_works(self, crypto_params):
        """Test that basic context serialization/deserialization works."""
        with CryptoContextManager(**crypto_params) as manager:
            cc = manager.get_context()
            pre.generate_keys(cc)
            serialized_data = manager.serialize_context()

            # Deserialize into a new manager
            with CryptoContextManager(serialized_data=serialized_data) as new_manager:
                deserialized_cc = new_manager.get_context()

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
                decrypted_data = pre.coefficients_to_bytes(
                    decrypted_coeffs, len(test_data)
                )

                assert decrypted_data == test_data

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_re_encryption_workflow_with_context_manager(self, crypto_params):
        """Test the full PRE workflow using a single context manager."""
        with CryptoContextManager(**crypto_params) as manager:
            shared_cc = manager.get_context()

            # Generate keys for Alice and Bob using the same context instance
            alice_keys = pre.generate_keys(shared_cc)
            bob_keys = pre.generate_keys(shared_cc)

            # Generate re-encryption key - this should work because all objects
            # were created with the same context instance
            re_key = pre.generate_re_encryption_key(
                shared_cc, alice_keys.secretKey, bob_keys.publicKey
            )
            assert re_key is not None

            # Test full workflow
            test_data = b"test data for pre workflow"
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

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_client_server_serialization_workflow(self, crypto_params):
        """Test the client-server serialization/deserialization workflow."""
        # Server initializes context and serializes it
        with CryptoContextManager(**crypto_params) as server_manager:
            pre.generate_keys(server_manager.get_context())
            serialized_context = server_manager.serialize_context()

        # Client deserializes the server's context
        with CryptoContextManager(serialized_data=serialized_context) as client_manager:
            client_cc = client_manager.get_context()

            # Verify client context works
            keys = pre.generate_keys(client_cc)
            assert keys.publicKey is not None
            assert keys.secretKey is not None

            # Verify serialization roundtrip
            client_serialized = client_manager.serialize_context()
            assert client_serialized == serialized_context


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
