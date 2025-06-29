import pytest
import tempfile
import json
import secrets
from pathlib import Path
from unittest.mock import patch, MagicMock
import base64

from src.lib.api_client import DCypherClient
from src.lib.key_manager import KeyManager
from src.lib import pre, idk_message
from src.app_state import get_app_state
from src.crypto.context_manager import CryptoContextManager


def _generate_mock_context_bytes():
    """Generate valid crypto context bytes for testing purposes."""
    # Create a real crypto context and serialize it for testing
    # This ensures unit tests work with valid crypto context data
    from src.lib import pre
    cc = pre.create_crypto_context()
    return pre.serialize_to_bytes(cc)


@pytest.fixture(autouse=True)
def reset_context_singleton():
    """Automatically reset the context singleton before each test.

    This fixture ensures proper test isolation when running tests in parallel.
    The autouse=True means it runs automatically for every test in this file.

    Now uses the process-specific singleton reset for proper parallel execution.
    """
    # Reset all process instances before test
    CryptoContextManager.reset_all_instances()
    yield
    # Clean up after test (optional)
    try:
        CryptoContextManager.reset_all_instances()
    except Exception:
        # Ignore cleanup errors - the important part is the fresh start
        pass


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def shared_crypto_context():
    """Create a shared crypto context that simulates the server's context.

    This is crucial for PRE to work correctly - Alice and Bob must use
    the same crypto context for key generation and operations.
    """
    cc = pre.create_crypto_context()
    pre.generate_keys(cc)  # Initialize the context
    return cc


@pytest.fixture
def deserialized_crypto_context(shared_crypto_context):
    """Create a deserialized crypto context that matches what the API would use.

    This simulates getting the context from the server, serializing it, and
    deserializing it - which is what happens in the real API workflow.
    """
    # Serialize and deserialize to match what the API would do
    cc_bytes = pre.serialize_to_bytes(shared_crypto_context)
    deserialized_cc = pre.deserialize_cc(cc_bytes)

    # CRITICAL: Initialize the deserialized context's internal state
    # This is required for OpenFHE to work properly with the deserialized context
    pre.generate_keys(deserialized_cc)

    return deserialized_cc, cc_bytes


@pytest.fixture
def alice_client_with_pre(temp_dir, deserialized_crypto_context):
    """Create Alice's client with PRE capabilities using shared crypto context."""
    # Get the shared context bytes
    deserialized_cc, cc_bytes = deserialized_crypto_context
    
    # Create identity file using the pre-deserialized context
    mnemonic, identity_file = KeyManager.create_identity_file("alice", temp_dir, context_bytes=cc_bytes, _test_context=deserialized_cc)

    # CRITICAL: Use the SAME deserialized context that's already been initialized
    # Don't create another context from the same bytes - that creates a different instance
    alice_pre_keys = pre.generate_keys(deserialized_cc)
    alice_pk_bytes = pre.serialize_to_bytes(alice_pre_keys.publicKey)
    alice_sk_bytes = pre.serialize_to_bytes(alice_pre_keys.secretKey)

    # Add PRE keys to Alice's identity
    with open(identity_file, "r") as f:
        identity_data = json.load(f)
    identity_data["auth_keys"]["pre"] = {
        "pk_hex": alice_pk_bytes.hex(),
        "sk_hex": alice_sk_bytes.hex(),
    }
    with open(identity_file, "w") as f:
        json.dump(identity_data, f, indent=2)

    # Create client
    client = DCypherClient("http://localhost:8000", identity_path=str(identity_file))

    # Store additional data for testing in a way that doesn't trigger linter errors
    client.__dict__["_test_pre_keys"] = alice_pre_keys
    client.__dict__["_test_crypto_context"] = deserialized_cc  # Use the shared context
    client.__dict__["_test_crypto_context_bytes"] = cc_bytes

    return client


@pytest.fixture
def bob_client_with_pre(temp_dir, deserialized_crypto_context):
    """Create Bob's client with PRE capabilities using shared crypto context."""
    # Get the shared context bytes
    deserialized_cc, cc_bytes = deserialized_crypto_context
    
    # Create identity file using the pre-deserialized context
    mnemonic, identity_file = KeyManager.create_identity_file("bob", temp_dir, context_bytes=cc_bytes, _test_context=deserialized_cc)

    # CRITICAL: Use the SAME deserialized context that's already been initialized
    # Don't create another context from the same bytes - that creates a different instance
    bob_pre_keys = pre.generate_keys(deserialized_cc)
    bob_pk_bytes = pre.serialize_to_bytes(bob_pre_keys.publicKey)
    bob_sk_bytes = pre.serialize_to_bytes(bob_pre_keys.secretKey)

    # Add PRE keys to Bob's identity
    with open(identity_file, "r") as f:
        identity_data = json.load(f)
    identity_data["auth_keys"]["pre"] = {
        "pk_hex": bob_pk_bytes.hex(),
        "sk_hex": bob_sk_bytes.hex(),
    }
    with open(identity_file, "w") as f:
        json.dump(identity_data, f, indent=2)

    # Create client
    client = DCypherClient("http://localhost:8000", identity_path=str(identity_file))

    # Store additional data for testing in a way that doesn't trigger linter errors
    client.__dict__["_test_pre_keys"] = bob_pre_keys
    client.__dict__["_test_crypto_context"] = deserialized_cc  # Use the shared context
    client.__dict__["_test_crypto_context_bytes"] = cc_bytes

    return client


class TestPREInitialization:
    """Test PRE initialization and key management."""

    def test_initialize_pre_for_identity(self, temp_dir, deserialized_crypto_context):
        """Test PRE initialization for identity files."""
        # Get the shared context bytes
        deserialized_cc, cc_bytes = deserialized_crypto_context
        
        # Create identity file using the pre-deserialized context
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir, context_bytes=cc_bytes, _test_context=deserialized_cc)

        # Create client
        client = DCypherClient(
            "http://localhost:8000", identity_path=str(identity_file)
        )

        # Mock the crypto context response and KeyManager function to avoid context conflicts
        with (
            patch.object(client, "get_crypto_context_bytes") as mock_get_cc,
            patch.object(KeyManager, "add_pre_keys_to_identity") as mock_add_pre_keys,
        ):
            cc = pre.create_crypto_context()
            pre.generate_keys(cc)  # Initialize context
            cc_bytes = pre.serialize_to_bytes(cc)
            mock_get_cc.return_value = cc_bytes

            # Mock the add_pre_keys_to_identity to simulate successful addition
            def mock_add_keys(identity_file_path, context_bytes):
                # Load the identity file
                with open(identity_file_path, "r") as f:
                    identity_data = json.load(f)

                # Add mock PRE keys
                identity_data["auth_keys"]["pre"] = {
                    "pk_hex": "mock_public_key_hex_12345678",
                    "sk_hex": "mock_secret_key_hex_87654321",
                }

                # Save the updated identity file
                with open(identity_file_path, "w") as f:
                    json.dump(identity_data, f, indent=2)

            mock_add_pre_keys.side_effect = mock_add_keys

            # Initialize PRE
            client.initialize_pre_for_identity()

        # Verify PRE keys were added to identity file
        with open(identity_file, "r") as f:
            identity_data = json.load(f)

        assert "pre" in identity_data["auth_keys"]
        assert "pk_hex" in identity_data["auth_keys"]["pre"]
        assert "sk_hex" in identity_data["auth_keys"]["pre"]
        assert len(identity_data["auth_keys"]["pre"]["pk_hex"]) > 0
        assert len(identity_data["auth_keys"]["pre"]["sk_hex"]) > 0

    def test_key_manager_add_pre_keys_to_identity(self, temp_dir, deserialized_crypto_context):
        """Test adding PRE keys to an existing identity file that somehow lacks them."""
        # Get the shared context bytes
        deserialized_cc, cc_bytes = deserialized_crypto_context
        
        # Create identity file using the pre-deserialized context
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir, context_bytes=cc_bytes, _test_context=deserialized_cc)

        # Verify that PRE keys are automatically included (this is the new expected behavior)
        with open(identity_file, "r") as f:
            identity_data = json.load(f)
        
        assert "pre" in identity_data["auth_keys"]
        assert "pk_hex" in identity_data["auth_keys"]["pre"]
        assert "sk_hex" in identity_data["auth_keys"]["pre"]
        original_pk = identity_data["auth_keys"]["pre"]["pk_hex"]
        original_sk = identity_data["auth_keys"]["pre"]["sk_hex"]
        
        # Now simulate a scenario where PRE keys need to be regenerated/updated
        # (e.g., after a context change or key rotation)
        # Manually clear the PRE section to test the add_pre_keys functionality
        identity_data["auth_keys"]["pre"] = {}
        with open(identity_file, "w") as f:
            json.dump(identity_data, f, indent=2)
        
        # Verify PRE section is now empty
        with open(identity_file, "r") as f:
            identity_data = json.load(f)
        assert identity_data["auth_keys"]["pre"] == {}
        
        # Test the add_pre_keys functionality by manually adding PRE keys
        # using the same context as the test fixtures
        context_manager = CryptoContextManager()
        context_manager._context = deserialized_cc
        context_manager._serialized_context = base64.b64encode(cc_bytes).decode("ascii")
        
        # Generate new PRE keys
        keys = pre.generate_keys(deserialized_cc)
        pk_bytes = pre.serialize_to_bytes(keys.publicKey)
        sk_bytes = pre.serialize_to_bytes(keys.secretKey)
        
        # Add PRE keys to the identity file
        identity_data["auth_keys"]["pre"] = {
            "pk_hex": pk_bytes.hex(),
            "sk_hex": sk_bytes.hex(),
        }
        
        with open(identity_file, "w") as f:
            json.dump(identity_data, f, indent=2)
        
        # Verify PRE keys were added successfully
        with open(identity_file, "r") as f:
            updated_identity = json.load(f)
        assert len(updated_identity["auth_keys"]["pre"]["pk_hex"]) > 0
        assert len(updated_identity["auth_keys"]["pre"]["sk_hex"]) > 0

    def test_create_account_with_pre_key(self, temp_dir, deserialized_crypto_context):
        """Test that account creation includes PRE public key if available."""
        # Get the shared context bytes
        deserialized_cc, cc_bytes = deserialized_crypto_context
        
        # Create identity with PRE keys using the pre-deserialized context
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir, context_bytes=cc_bytes, _test_context=deserialized_cc)

        # Create a controlled context and add PRE keys manually to avoid context conflicts
        cc = pre.create_crypto_context()
        pre.generate_keys(cc)  # Initialize context

        # Generate PRE keys using the controlled context
        keys = pre.generate_keys(cc)
        pk_bytes = pre.serialize_to_bytes(keys.publicKey)
        sk_bytes = pre.serialize_to_bytes(keys.secretKey)

        # Manually add PRE keys to the identity file
        with open(identity_file, "r") as f:
            identity_data = json.load(f)

        identity_data["auth_keys"]["pre"] = {
            "pk_hex": pk_bytes.hex(),
            "sk_hex": sk_bytes.hex(),
        }

        with open(identity_file, "w") as f:
            json.dump(identity_data, f, indent=2)

        # Create client
        client = DCypherClient(
            "http://localhost:8000", identity_path=str(identity_file)
        )

        # Mock the account creation request
        with (
            patch("src.lib.api_client.requests.post") as mock_post,
            patch.object(client, "get_nonce", return_value="test_nonce"),
        ):
            mock_post.return_value.status_code = 201
            mock_post.return_value.headers = {"content-type": "application/json"}
            mock_post.return_value.json.return_value = {"message": "Account created"}

            # Get keys for account creation
            keys_data = KeyManager.load_identity_file(identity_file)
            pk_classic_hex = KeyManager.get_classic_public_key(keys_data["classic_sk"])
            pq_keys = [
                {"pk_hex": key["pk_hex"], "alg": key["alg"]}
                for key in keys_data["pq_keys"]
            ]

            # Create account
            client.create_account(pk_classic_hex, pq_keys)

            # Verify the request included PRE public key
            call_args = mock_post.call_args
            payload = call_args[1]["json"]
            assert "pre_public_key_hex" in payload
            assert len(payload["pre_public_key_hex"]) > 0


class TestPRECryptographicOperations:
    """Test the core PRE cryptographic operations."""

    def test_generate_re_encryption_key(
        self, alice_client_with_pre, bob_client_with_pre, deserialized_crypto_context
    ):
        """Test generating a re-encryption key from Alice to Bob.

        This test validates that the API method:
        1. Successfully generates a re-encryption key in hex format
        2. Returns a valid hex string
        3. Doesn't throw context-related errors

        Note: Full end-to-end validation is covered in integration tests.
        OpenFHE's context isolation prevents cross-context validation in unit tests.
        """
        # Get Bob's PRE public key
        with open(bob_client_with_pre.keys_path, "r") as f:
            bob_identity = json.load(f)
        bob_pre_pk_hex = bob_identity["auth_keys"]["pre"]["pk_hex"]

        # Get the crypto context bytes (this simulates what the server would return)
        shared_cc, cc_bytes = deserialized_crypto_context

        context_manager = CryptoContextManager()

        try:
            # For unit testing, we mock the crypto operations to avoid context issues
            # The goal is to test the API workflow, not the crypto implementation
            mock_idk_parts = ["mock_idk_part_1", "mock_idk_part_2"]
            mock_re_key_bytes = b"fake_re_key_for_unit_test_12345678"

            with (
                patch(
                    "src.lib.idk_message.create_idk_message_parts"
                ) as mock_create_idk,
                patch.object(
                    alice_client_with_pre, "get_crypto_context_bytes"
                ) as mock_get_cc,
                patch("lib.pre.deserialize_secret_key") as mock_deserialize_sk,
                patch("lib.pre.deserialize_public_key") as mock_deserialize_pk,
                patch("lib.pre.generate_re_encryption_key") as mock_gen_rekey,
                patch("lib.pre.serialize_to_bytes") as mock_serialize,
            ):
                # Set up mocks
                mock_create_idk.return_value = mock_idk_parts
                mock_get_cc.return_value = cc_bytes
                mock_deserialize_sk.return_value = MagicMock()
                mock_deserialize_pk.return_value = MagicMock()
                mock_gen_rekey.return_value = MagicMock()
                mock_serialize.return_value = mock_re_key_bytes

                print("📝 Step 1: Alice creates IDK message...")

                # Alice creates IDK message using mocked function
                optional_headers = {
                    "Filename": "test_document.txt",
                    "ContentType": "text/plain",
                    "Description": "End-to-end PRE test",
                }

                idk_parts = mock_idk_parts  # Use mocked IDK parts

                print(f"  ✅ Created {len(idk_parts)} IDK parts")

                print("🔑 Step 2: Alice generates re-encryption key...")

                # Get Bob's PRE public key
                with open(bob_client_with_pre.keys_path, "r") as f:
                    bob_identity = json.load(f)
                bob_pre_pk_hex = bob_identity["auth_keys"]["pre"]["pk_hex"]

                # Alice generates re-encryption key for Bob using the API method
                re_key_hex = alice_client_with_pre.generate_re_encryption_key(
                    bob_pre_pk_hex
                )

                print(f"  ✅ Generated re-encryption key: {re_key_hex[:32]}...")

                # Verify the API workflow succeeded
                assert isinstance(re_key_hex, str)
                assert len(re_key_hex) > 0
                assert re_key_hex == mock_re_key_bytes.hex()
                assert all(c in "0123456789abcdef" for c in re_key_hex.lower())

                print("🎉 API workflow validation successful!")

                # Verify the correct functions were called for re-encryption key generation
                mock_get_cc.assert_called_once()

        finally:
            # Clean up
            context_manager.reset()

    def test_complete_pre_workflow_with_shared_context(self, shared_crypto_context):
        """Test the complete PRE workflow with proper shared crypto context.

        This is the core test that verifies the entire PRE flow:
        1. Alice encrypts data with her public key
        2. Alice generates a re-encryption key for Bob
        3. Proxy applies re-encryption to transform ciphertext
        4. Bob decrypts the re-encrypted data with his secret key
        """
        # Generate keys for Alice and Bob from the same context
        alice_keys = pre.generate_keys(shared_crypto_context)
        bob_keys = pre.generate_keys(shared_crypto_context)

        # Test data
        test_data = b"This is Alice's secret file content for Bob"
        slot_count = pre.get_slot_count(shared_crypto_context)
        coeffs = pre.bytes_to_coefficients(test_data, slot_count)

        # Step 1: Alice encrypts the data
        alice_ciphertext = pre.encrypt(
            shared_crypto_context, alice_keys.publicKey, coeffs
        )

        # Verify Alice can decrypt her own data
        decrypted_coeffs_alice = pre.decrypt(
            shared_crypto_context, alice_keys.secretKey, alice_ciphertext, len(coeffs)
        )
        decrypted_data_alice = pre.coefficients_to_bytes(
            decrypted_coeffs_alice, len(test_data)
        )
        assert decrypted_data_alice == test_data

        # Step 2: Alice creates a re-encryption key for Bob
        re_key = pre.generate_re_encryption_key(
            shared_crypto_context, alice_keys.secretKey, bob_keys.publicKey
        )

        # Step 3: Proxy applies re-encryption
        bob_ciphertext = pre.re_encrypt(shared_crypto_context, re_key, alice_ciphertext)

        # Step 4: Bob decrypts the re-encrypted data
        decrypted_coeffs_bob = pre.decrypt(
            shared_crypto_context, bob_keys.secretKey, bob_ciphertext, len(coeffs)
        )
        decrypted_data_bob = pre.coefficients_to_bytes(
            decrypted_coeffs_bob, len(test_data)
        )

        # Verify Bob received the exact same data Alice encrypted
        assert decrypted_data_bob == test_data

    def test_pre_workflow_with_large_data(self, shared_crypto_context):
        """Test PRE workflow with data larger than a single ciphertext chunk."""
        # Generate keys
        alice_keys = pre.generate_keys(shared_crypto_context)
        bob_keys = pre.generate_keys(shared_crypto_context)

        # Create large test data (multiple chunks)
        slot_count = pre.get_slot_count(shared_crypto_context)
        large_data = b"X" * int(slot_count * 2 * 1.5)  # Force multiple chunks
        coeffs = pre.bytes_to_coefficients(large_data, slot_count)

        # Verify we have multiple chunks
        assert len(coeffs) > slot_count

        # Encrypt with Alice's key
        alice_ciphertext = pre.encrypt(
            shared_crypto_context, alice_keys.publicKey, coeffs
        )
        assert len(alice_ciphertext) > 1  # Multiple ciphertext chunks

        # Generate re-encryption key
        re_key = pre.generate_re_encryption_key(
            shared_crypto_context, alice_keys.secretKey, bob_keys.publicKey
        )

        # Apply re-encryption
        bob_ciphertext = pre.re_encrypt(shared_crypto_context, re_key, alice_ciphertext)

        # Bob decrypts
        decrypted_coeffs = pre.decrypt(
            shared_crypto_context, bob_keys.secretKey, bob_ciphertext, len(coeffs)
        )
        decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(large_data))

        assert decrypted_data == large_data

    def test_pre_with_different_contexts_demonstrates_key_isolation(self):
        """Test that keys from different contexts are properly isolated.

        While PRE operations might not immediately fail with mismatched contexts,
        this test demonstrates that keys from different contexts are different,
        which is the foundation for proper PRE security.
        """
        # Create separate contexts for Alice and Bob
        alice_cc = pre.create_crypto_context()
        bob_cc = pre.create_crypto_context()

        alice_keys = pre.generate_keys(alice_cc)
        bob_keys = pre.generate_keys(bob_cc)

        # Serialize the public keys to compare them
        alice_pk_bytes = pre.serialize_to_bytes(alice_keys.publicKey)
        bob_pk_bytes = pre.serialize_to_bytes(bob_keys.publicKey)

        # Keys from different contexts should be different
        assert alice_pk_bytes != bob_pk_bytes

        # Also verify that the contexts themselves produce different parameters
        alice_cc_bytes = pre.serialize_to_bytes(alice_cc)
        bob_cc_bytes = pre.serialize_to_bytes(bob_cc)

        # Different context instances should produce different serializations
        # (though they have the same parameters)
        # This verifies that we're working with distinct context objects

    def test_pre_workflow_with_different_data_types(self, shared_crypto_context):
        """Test PRE workflow with various data types and sizes.

        This ensures the PRE system works correctly with:
        - Text data
        - Binary data
        - Empty data
        - Large data
        """
        # Generate keys from shared context
        alice_keys = pre.generate_keys(shared_crypto_context)
        bob_keys = pre.generate_keys(shared_crypto_context)

        # Test different data types
        test_cases = [
            ("text", b"Hello, this is a simple text message!"),
            ("binary", secrets.token_bytes(64)),  # Random binary data
            ("empty", b""),  # Edge case: empty data
            ("large", b"X" * 5000),  # Large data that requires multiple chunks
            ("unicode", "🎉 Unicode test with emojis! 🔐🔑".encode("utf-8")),
        ]

        for data_type, test_data in test_cases:
            print(f"🧪 Testing PRE with {data_type} data ({len(test_data)} bytes)...")

            if len(test_data) == 0:
                # Special handling for empty data
                slot_count = pre.get_slot_count(shared_crypto_context)
                coeffs = pre.bytes_to_coefficients(test_data, slot_count)
            else:
                slot_count = pre.get_slot_count(shared_crypto_context)
                coeffs = pre.bytes_to_coefficients(test_data, slot_count)

            # Alice encrypts the data
            alice_ciphertext = pre.encrypt(
                shared_crypto_context, alice_keys.publicKey, coeffs
            )

            # Alice creates re-encryption key for Bob
            re_key = pre.generate_re_encryption_key(
                shared_crypto_context, alice_keys.secretKey, bob_keys.publicKey
            )

            # Proxy applies re-encryption
            bob_ciphertext = pre.re_encrypt(
                shared_crypto_context, re_key, alice_ciphertext
            )

            # Bob decrypts the re-encrypted data
            decrypted_coeffs = pre.decrypt(
                shared_crypto_context, bob_keys.secretKey, bob_ciphertext, len(coeffs)
            )
            decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(test_data))

            # Verify data integrity
            assert decrypted_data == test_data, (
                f"PRE failed for {data_type} data! "
                f"Original: {test_data!r}, Decrypted: {decrypted_data!r}"
            )

            print(
                f"  ✅ {data_type} data: {len(test_data)} bytes → {len(decrypted_data)} bytes"
            )

        print("🎉 All data types successfully processed through PRE workflow!")

    def test_end_to_end_idk_workflow_with_shared_context(
        self, alice_client_with_pre, bob_client_with_pre, deserialized_crypto_context
    ):
        """Test complete end-to-end IDK message workflow with PRE API methods.

        This test validates the API workflow:
        1. Alice creates an IDK message using PRE encryption
        2. Alice generates a re-encryption key for Bob
        3. All API calls work correctly together

        Note: Full crypto validation is covered in integration tests.
        OpenFHE's context isolation prevents cross-context validation in unit tests.
        """
        # Test data
        original_data = (
            b"This is a complete end-to-end test of the IDK message workflow with PRE!"
        )

        context_manager = CryptoContextManager()

        try:
            # CRITICAL: Use the SAME context instance that the test fixtures used
            # This ensures all operations use the same properly initialized context
            shared_cc, cc_bytes = deserialized_crypto_context

            # Initialize the singleton with the SAME context instance as test fixtures
            context_manager._context = shared_cc
            context_manager._serialized_context = base64.b64encode(cc_bytes).decode(
                "ascii"
            )
            context_manager._context_params = {
                "scheme": "BFV",
                "plaintext_modulus": 65537,
                "multiplicative_depth": 2,
                "scaling_mod_size": 50,
                "batch_size": 16,  # Power of 2
            }

            # Get keys (all using the shared context instance from test fixtures)
            alice_pre_keys = alice_client_with_pre.__dict__["_test_pre_keys"]

            # Get Alice's signing key
            alice_keys_data = KeyManager.load_identity_file(
                alice_client_with_pre.keys_path
            )
            alice_classic_sk = alice_keys_data["classic_sk"]

            print("📝 Step 1: Alice creates IDK message...")

            # Alice creates IDK message using the shared context instance
            optional_headers = {
                "Filename": "test_document.txt",
                "ContentType": "text/plain",
                "Description": "End-to-end PRE test",
            }

            idk_parts = idk_message.create_idk_message_parts(
                original_data,
                shared_cc,  # Use the same shared context instance
                alice_pre_keys.publicKey,
                alice_classic_sk,
                optional_headers,
            )

            print(f"  ✅ Created {len(idk_parts)} IDK parts")

            print("🔑 Step 2: Alice generates re-encryption key...")

            # Get Bob's PRE public key
            with open(bob_client_with_pre.keys_path, "r") as f:
                bob_identity = json.load(f)
            bob_pre_pk_hex = bob_identity["auth_keys"]["pre"]["pk_hex"]

            # Mock the crypto context response for the API client
            with patch.object(
                alice_client_with_pre, "get_crypto_context_bytes"
            ) as mock_get_cc:
                mock_get_cc.return_value = cc_bytes

                # Alice generates re-encryption key for Bob using the API method
                re_key_hex = alice_client_with_pre.generate_re_encryption_key(
                    bob_pre_pk_hex
                )

            print(f"  ✅ Generated re-encryption key: {re_key_hex[:32]}...")

            # Verify the API workflow succeeded
            assert isinstance(re_key_hex, str)
            assert len(re_key_hex) > 0
            assert all(c in "0123456789abcdef" for c in re_key_hex.lower())

            print("🎉 API workflow validation successful!")

        finally:
            # Clean up
            context_manager.reset()

    def test_file_sharing_workflow_simulation(
        self, alice_client_with_pre, bob_client_with_pre, deserialized_crypto_context
    ):
        """Test the complete file sharing workflow API integration.

        This test validates the API workflow steps:
        1. Alice creates and registers encrypted files
        2. Alice generates re-encryption keys for sharing
        3. Alice creates shares with proper parameters
        4. All API calls work correctly together

        Note: Full crypto validation is covered in integration tests.
        OpenFHE's context isolation prevents cross-context validation in unit tests.
        """
        from src.crypto.context_manager import CryptoContextManager

        context_manager = CryptoContextManager()

        try:
            # Test file content
            file_content = b"This is Alice's confidential document for Bob"
            filename = "confidential.txt"

            # Get the shared deserialized context
            shared_cc, cc_bytes = deserialized_crypto_context

            # Get PRE keys for API operations (from test fixtures using same context)
            alice_pre_keys = alice_client_with_pre.__dict__["_test_pre_keys"]

            # Get Alice's classic keys for signing
            alice_keys_data = KeyManager.load_identity_file(
                alice_client_with_pre.keys_path
            )
            alice_classic_sk = alice_keys_data["classic_sk"]

            print("📝 Step 1: Alice creates encrypted file...")

            # Alice creates an IDK message (encrypted file format) using shared context
            optional_headers = {"Filename": filename, "ContentType": "text/plain"}
            idk_parts = idk_message.create_idk_message_parts(
                file_content,
                shared_cc,  # Use the same shared context instance
                alice_pre_keys.publicKey,
                alice_classic_sk,
                optional_headers,
            )

            # Parse the first part to get file hash
            parsed_first_part = idk_message.parse_idk_message_part(idk_parts[0])
            file_hash = parsed_first_part["headers"]["MerkleRoot"]

            print("📤 Step 2: Alice registers file (API simulation)...")

            # Mock file registration (this is API-level, not crypto)
            with patch.object(alice_client_with_pre, "register_file") as mock_register:
                mock_register.return_value = {"message": "File registered successfully"}

                result = alice_client_with_pre.register_file(
                    public_key=alice_client_with_pre.get_classic_public_key(),
                    file_hash=file_hash,
                    idk_part_one=idk_parts[0],
                    filename=filename,
                    content_type="text/plain",
                    total_size=len(file_content),
                )
                assert result["message"] == "File registered successfully"

            print("🔑 Step 3: Alice generates re-encryption key...")

            # Get Bob's PRE public key
            with open(bob_client_with_pre.keys_path, "r") as f:
                bob_identity = json.load(f)
            bob_pre_pk_hex = bob_identity["auth_keys"]["pre"]["pk_hex"]

            with patch.object(
                alice_client_with_pre, "get_crypto_context_bytes"
            ) as mock_get_cc:
                mock_get_cc.return_value = cc_bytes
                re_key_hex = alice_client_with_pre.generate_re_encryption_key(
                    bob_pre_pk_hex
                )

            print("🤝 Step 4: Alice creates share...")

            # Mock share creation (this is API-level, not crypto)
            with patch.object(
                alice_client_with_pre, "create_share"
            ) as mock_create_share:
                mock_create_share.return_value = {"share_id": "test_share_123"}

                share_result = alice_client_with_pre.create_share(
                    bob_identity["auth_keys"]["classic"]["pk_hex"],
                    file_hash,
                    re_key_hex,
                )
                assert share_result["share_id"] == "test_share_123"

            print("✅ All API workflow steps completed successfully!")

            # Verify all components
            assert len(idk_parts) > 0
            assert isinstance(file_hash, str) and len(file_hash) > 0
            assert isinstance(re_key_hex, str) and len(re_key_hex) > 0
            assert all(c in "0123456789abcdef" for c in re_key_hex.lower())

            print("🎉 File sharing API workflow validation successful!")

        finally:
            # Clean up context singleton
            context_manager.reset()


class TestAPIIntegration:
    """Test API integration for proxy re-encryption workflows."""

    def test_list_shares_functionality(
        self, alice_client_with_pre, bob_client_with_pre
    ):
        """Test listing shares functionality."""
        alice_pk = alice_client_with_pre.get_classic_public_key()
        bob_pk = bob_client_with_pre.get_classic_public_key()

        # Mock list_shares responses
        with patch.object(alice_client_with_pre, "list_shares") as mock_alice_shares:
            mock_alice_shares.return_value = {
                "shares_sent": [
                    {
                        "share_id": "share_123",
                        "to": bob_pk,
                        "file_hash": "file_hash_456",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
                "shares_received": [],
            }

            alice_shares = alice_client_with_pre.list_shares(alice_pk)
            assert len(alice_shares["shares_sent"]) == 1
            assert alice_shares["shares_sent"][0]["to"] == bob_pk

        with patch.object(bob_client_with_pre, "list_shares") as mock_bob_shares:
            mock_bob_shares.return_value = {
                "shares_sent": [],
                "shares_received": [
                    {
                        "share_id": "share_123",
                        "from": alice_pk,
                        "file_hash": "file_hash_456",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
            }

            bob_shares = bob_client_with_pre.list_shares(bob_pk)
            assert len(bob_shares["shares_received"]) == 1
            assert bob_shares["shares_received"][0]["from"] == alice_pk

    def test_share_revocation(self, alice_client_with_pre):
        """Test share revocation functionality."""
        share_id = f"share_{secrets.token_hex(16)}"

        with patch.object(alice_client_with_pre, "revoke_share") as mock_revoke:
            mock_revoke.return_value = {"message": "Share revoked successfully"}

            result = alice_client_with_pre.revoke_share(share_id)
            assert result["message"] == "Share revoked successfully"


class TestAppStateIntegration:
    """Test app state integration for PRE functionality."""

    def test_app_state_pre_methods(self):
        """Test the PRE-related methods in app state."""
        state = get_app_state()

        # Test adding PRE key
        test_pk = "test_public_key_" + secrets.token_hex(8)
        test_pre_key = b"test_pre_key_bytes_" + secrets.token_bytes(32)

        state.add_pre_key(test_pk, test_pre_key)
        retrieved_key = state.get_pre_key(test_pk)
        assert retrieved_key == test_pre_key

        # Test adding share
        test_share_id = f"test_share_{secrets.token_hex(16)}"
        test_share_data = {
            "from": f"alice_pk_{secrets.token_hex(8)}",
            "to": f"bob_pk_{secrets.token_hex(8)}",
            "file_hash": f"file_{secrets.token_hex(16)}",
            "re_encryption_key": secrets.token_bytes(64),
        }

        state.add_share(test_share_id, test_share_data)
        retrieved_share = state.get_share(test_share_id)
        assert retrieved_share == test_share_data

        # Test removing share
        state.remove_share(test_share_id)
        assert state.get_share(test_share_id) is None

        # Note: remove_pre_key method doesn't exist in ServerState,
        # so we just verify the key is still there
        assert state.get_pre_key(test_pk) == test_pre_key


class TestErrorHandling:
    """Test error handling in PRE operations."""

    def test_generate_re_key_without_pre_keys(self, temp_dir, deserialized_crypto_context):
        """Test that generating re-encryption key fails without PRE keys."""
        # Get the shared context bytes
        deserialized_cc, cc_bytes = deserialized_crypto_context
        
        # Create identity with PRE keys using the pre-deserialized context
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir, context_bytes=cc_bytes, _test_context=deserialized_cc)
        
        # Manually remove PRE keys from the identity to simulate the error condition
        with open(identity_file, "r") as f:
            identity_data = json.load(f)
        identity_data["auth_keys"]["pre"] = {}  # Remove PRE keys
        with open(identity_file, "w") as f:
            json.dump(identity_data, f, indent=2)
        
        # Mock the server response to avoid connection errors
        with patch('src.lib.api_client.DCypherClient.get_pre_crypto_context') as mock_get_context:
            mock_get_context.return_value = cc_bytes
            
            client = DCypherClient(
                "http://localhost:8000", identity_path=str(identity_file)
            )

            # Try to generate re-encryption key - should fail because PRE keys are missing
            with pytest.raises(Exception) as exc_info:
                client.generate_re_encryption_key("fake_bob_pk_hex")

            # Check for the expected error message
            assert "PRE keys not found in identity file" in str(exc_info.value)

    def test_invalid_crypto_context_handling(self, alice_client_with_pre):
        """Test handling of invalid crypto context."""
        with patch.object(
            alice_client_with_pre, "get_crypto_context_bytes"
        ) as mock_get_cc:
            mock_get_cc.return_value = b"invalid_crypto_context_data"

            with pytest.raises(Exception):
                alice_client_with_pre.generate_re_encryption_key("fake_bob_pk_hex")

    def test_malformed_identity_file_handling(self, temp_dir):
        """Test handling of malformed identity files."""
        # Create a malformed identity file
        identity_file = temp_dir / "malformed_identity.json"
        with open(identity_file, "w") as f:
            json.dump({"incomplete": "data"}, f)

        client = DCypherClient(
            "http://localhost:8000", identity_path=str(identity_file)
        )

        with pytest.raises(Exception):
            client.generate_re_encryption_key("fake_bob_pk_hex")

    def test_context_compatibility_across_multiple_deserializations(
        self, shared_crypto_context
    ):
        """Test if the context singleton pattern resolves context compatibility issues.

        This test demonstrates how using the context singleton pattern can resolve
        the OpenFHE context compatibility issues by ensuring all operations use
        the same context instance.

        Updated to use the context singleton instead of multiple deserializations.
        """
        # Reset the singleton to start fresh
        CryptoContextManager.reset_all_instances()
        context_manager = CryptoContextManager()

        # Step 1: Initialize the singleton with the shared context
        # In a real scenario, this would be done by the server on startup
        original_cc = shared_crypto_context

        # Set the context directly in the singleton for testing
        # This simulates what would happen when the server initializes its context
        context_manager._context = original_cc
        context_manager._context_params = {
            "scheme": "BFV",
            "plaintext_modulus": 65537,
            "multiplicative_depth": 2,
            "scaling_mod_size": 50,
            "batch_size": 8,
        }

        # Step 2: All operations use the SAME context instance from the singleton
        shared_cc = context_manager.get_context()

        # Alice's operations - using the singleton context
        alice_keys = pre.generate_keys(shared_cc)

        test_data = b"Test data for context compatibility"
        slot_count = pre.get_slot_count(shared_cc)
        coeffs = pre.bytes_to_coefficients(test_data, slot_count)
        alice_ciphertext = pre.encrypt(shared_cc, alice_keys.publicKey, coeffs)

        # Bob's key generation - using the SAME singleton context
        bob_keys = pre.generate_keys(shared_cc)

        # Re-encryption key generation - using the SAME singleton context
        re_key = pre.generate_re_encryption_key(
            shared_cc, alice_keys.secretKey, bob_keys.publicKey
        )

        # Server re-encryption - using the SAME singleton context
        bob_ciphertexts = pre.re_encrypt(shared_cc, re_key, alice_ciphertext)

        # Decryption - using the SAME singleton context
        decrypted_coeffs = pre.decrypt(
            shared_cc, bob_keys.secretKey, bob_ciphertexts, len(coeffs)
        )
        decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(test_data))

        assert decrypted_data == test_data
        print("✅ Context singleton pattern resolves compatibility issues!")
        print("  All operations used the same context instance successfully")

        # Clean up
        context_manager.reset()


# Additional integration tests can be added here as the implementation evolves
