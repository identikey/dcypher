import pytest
import tempfile
import json
import secrets
from pathlib import Path
from unittest.mock import patch, MagicMock
import base64

from dcypher.lib.api_client import DCypherClient
from dcypher.lib.key_manager import KeyManager
from dcypher.lib import pre, idk_message
from dcypher.app_state import get_app_state
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
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def server_context_manager(crypto_params):
    """Simulates a server's crypto context, providing both the manager and serialized data."""
    if not OPENFHE_AVAILABLE:
        pytest.skip("OpenFHE not available")
    with CryptoContextManager(**crypto_params) as manager:
        pre.generate_keys(manager.get_context())  # Initialize context fully
        serialized_context = manager.serialize_context()
        yield manager, serialized_context


@pytest.fixture
def alice_identity(temp_dir, server_context_manager):
    """Creates a PRE-enabled identity for Alice using the server's context."""
    manager, serialized_context = server_context_manager
    context_bytes = base64.b64decode(serialized_context.encode("ascii"))

    mnemonic, identity_file = KeyManager.create_identity_file(
        "alice",
        temp_dir,
        context_bytes=context_bytes,
    )
    return identity_file


@pytest.fixture
def bob_identity(temp_dir, server_context_manager):
    """Creates a PRE-enabled identity for Bob using the server's context."""
    manager, serialized_context = server_context_manager
    context_bytes = base64.b64decode(serialized_context.encode("ascii"))

    mnemonic, identity_file = KeyManager.create_identity_file(
        "bob",
        temp_dir,
        context_bytes=context_bytes,
    )
    return identity_file


class TestPREInitialization:
    """Test PRE initialization and key management."""

    def test_identity_creation_includes_pre_keys(self, alice_identity):
        """Verify that creating an identity with a context automatically includes PRE keys."""
        with open(alice_identity, "r") as f:
            identity_data = json.load(f)

        assert "pre" in identity_data["auth_keys"]
        assert "pk_hex" in identity_data["auth_keys"]["pre"]
        assert "sk_hex" in identity_data["auth_keys"]["pre"]
        assert len(identity_data["auth_keys"]["pre"]["pk_hex"]) > 0

    def test_add_pre_keys_to_identity(self, temp_dir, server_context_manager):
        """Test adding PRE keys to an identity that lacks them."""
        manager, serialized_context = server_context_manager
        context_bytes = base64.b64decode(serialized_context.encode("ascii"))

        # Create an identity, but we will manually remove the PRE keys
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_user", temp_dir, context_bytes=context_bytes
        )
        with open(identity_file, "r+") as f:
            identity_data = json.load(f)
            if "auth_keys" not in identity_data:
                identity_data["auth_keys"] = {}
            identity_data["auth_keys"]["pre"] = {}
            f.seek(0)
            json.dump(identity_data, f)
            f.truncate()

        # Now, add PRE keys using the specific function
        KeyManager.add_pre_keys_to_identity(identity_file, cc_bytes=context_bytes)

        with open(identity_file, "r") as f:
            updated_identity = json.load(f)

        assert "pre" in updated_identity["auth_keys"]
        assert "pk_hex" in updated_identity["auth_keys"]["pre"]
        assert len(updated_identity["auth_keys"]["pre"]["pk_hex"]) > 0


class TestPRECryptographicOperations:
    """Test the core PRE cryptographic operations."""

    def test_complete_pre_workflow(
        self, server_context_manager, alice_identity, bob_identity
    ):
        """Test the complete PRE workflow with proper shared crypto context."""
        manager, _ = server_context_manager
        shared_cc = manager.get_context()

        # Load raw identity data from files
        with open(alice_identity, "r") as f:
            alice_keys_data = json.load(f)
        with open(bob_identity, "r") as f:
            bob_keys_data = json.load(f)

        alice_sk_bytes = bytes.fromhex(alice_keys_data["auth_keys"]["pre"]["sk_hex"])
        bob_sk_bytes = bytes.fromhex(bob_keys_data["auth_keys"]["pre"]["sk_hex"])
        bob_pk_bytes = bytes.fromhex(bob_keys_data["auth_keys"]["pre"]["pk_hex"])

        alice_secret_key = pre.deserialize_secret_key(alice_sk_bytes)
        bob_secret_key = pre.deserialize_secret_key(bob_sk_bytes)
        bob_public_key = pre.deserialize_public_key(bob_pk_bytes)

        # Test data
        test_data = b"This is Alice's secret file content for Bob"
        slot_count = pre.get_slot_count(shared_cc)
        coeffs = pre.bytes_to_coefficients(test_data, slot_count)

        # Alice encrypts data (using a newly deserialized key for realism)
        alice_pk_bytes_from_id = bytes.fromhex(
            alice_keys_data["auth_keys"]["pre"]["pk_hex"]
        )
        alice_public_key = pre.deserialize_public_key(alice_pk_bytes_from_id)
        alice_ciphertext = pre.encrypt(shared_cc, alice_public_key, coeffs)

        # Alice creates a recryption key for Bob
        re_key = pre.generate_re_encryption_key(
            shared_cc, alice_secret_key, bob_public_key
        )

        # Proxy applies recryption
        bob_ciphertext = pre.re_encrypt(shared_cc, re_key, alice_ciphertext)

        # Bob decrypts the recrypted data
        decrypted_coeffs_bob = pre.decrypt(
            shared_cc, bob_secret_key, bob_ciphertext, len(coeffs)
        )
        decrypted_data_bob = pre.coefficients_to_bytes(
            decrypted_coeffs_bob, len(test_data)
        )

        assert decrypted_data_bob == test_data


class TestErrorHandling:
    """Test error handling in PRE operations."""

    def test_context_compatibility_with_new_manager(self, crypto_params):
        """Test if the new context manager ensures context compatibility."""
        with CryptoContextManager(**crypto_params) as manager:
            shared_cc = manager.get_context()
            alice_keys = pre.generate_keys(shared_cc)
            bob_keys = pre.generate_keys(shared_cc)

            test_data = b"Test data for context compatibility"
            slot_count = pre.get_slot_count(shared_cc)
            coeffs = pre.bytes_to_coefficients(test_data, slot_count)
            alice_ciphertext = pre.encrypt(shared_cc, alice_keys.publicKey, coeffs)

            re_key = pre.generate_re_encryption_key(
                shared_cc, alice_keys.secretKey, bob_keys.publicKey
            )
            bob_ciphertexts = pre.re_encrypt(shared_cc, re_key, alice_ciphertext)
            decrypted_coeffs = pre.decrypt(
                shared_cc, bob_keys.secretKey, bob_ciphertexts, len(coeffs)
            )
            decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(test_data))

            assert decrypted_data == test_data
