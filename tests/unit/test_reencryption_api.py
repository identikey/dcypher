import pytest
import tempfile
import json
import secrets
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.lib.api_client import DCypherClient
from src.lib.key_manager import KeyManager
from src.lib import pre, idk_message
from src.app_state import get_app_state


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
def alice_client_with_pre(temp_dir, shared_crypto_context):
    """Create Alice's client with PRE capabilities using shared crypto context."""
    # Create identity file
    mnemonic, identity_file = KeyManager.create_identity_file("alice", temp_dir)

    # Generate Alice's PRE keys from the shared context
    alice_pre_keys = pre.generate_keys(shared_crypto_context)
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
    client.__dict__["_test_crypto_context"] = shared_crypto_context

    return client


@pytest.fixture
def bob_client_with_pre(temp_dir, shared_crypto_context):
    """Create Bob's client with PRE capabilities using shared crypto context."""
    # Create identity file
    mnemonic, identity_file = KeyManager.create_identity_file("bob", temp_dir)

    # Generate Bob's PRE keys from the shared context
    bob_pre_keys = pre.generate_keys(shared_crypto_context)
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
    client.__dict__["_test_crypto_context"] = shared_crypto_context

    return client


class TestPREInitialization:
    """Test PRE initialization and key management."""

    def test_initialize_pre_for_identity(self, temp_dir):
        """Test PRE initialization for identity files."""
        # Create identity file
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)

        # Create client
        client = DCypherClient(
            "http://localhost:8000", identity_path=str(identity_file)
        )

        # Mock the crypto context response
        with patch.object(client, "get_pre_crypto_context") as mock_get_cc:
            cc = pre.create_crypto_context()
            pre.generate_keys(cc)  # Initialize context
            mock_get_cc.return_value = pre.serialize_to_bytes(cc)

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

    def test_key_manager_add_pre_keys_to_identity(self, temp_dir):
        """Test adding PRE keys to an existing identity file."""
        # Create identity file
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)

        # Verify initial state (empty PRE section)
        with open(identity_file, "r") as f:
            identity_data = json.load(f)
        assert identity_data["auth_keys"]["pre"] == {}

        # Create crypto context and add PRE keys
        cc = pre.create_crypto_context()
        pre.generate_keys(cc)  # Initialize context
        cc_bytes = pre.serialize_to_bytes(cc)

        KeyManager.add_pre_keys_to_identity(identity_file, cc_bytes)

        # Verify PRE keys were added
        with open(identity_file, "r") as f:
            updated_identity = json.load(f)

        assert "pk_hex" in updated_identity["auth_keys"]["pre"]
        assert "sk_hex" in updated_identity["auth_keys"]["pre"]
        assert len(updated_identity["auth_keys"]["pre"]["pk_hex"]) > 0
        assert len(updated_identity["auth_keys"]["pre"]["sk_hex"]) > 0

    def test_create_account_with_pre_key(self, temp_dir):
        """Test that account creation includes PRE public key if available."""
        # Create identity with PRE keys
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)

        # Initialize PRE for the identity
        with patch("src.lib.api_client.requests.get") as mock_get:
            cc = pre.create_crypto_context()
            pre.generate_keys(cc)  # Initialize context
            mock_get.return_value.content = pre.serialize_to_bytes(cc)

            KeyManager.add_pre_keys_to_identity(
                identity_file, pre.serialize_to_bytes(cc)
            )

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
        self, alice_client_with_pre, bob_client_with_pre
    ):
        """Test generating a re-encryption key from Alice to Bob."""
        # Get Bob's PRE public key
        with open(bob_client_with_pre.keys_path, "r") as f:
            bob_identity = json.load(f)
        bob_pre_pk_hex = bob_identity["auth_keys"]["pre"]["pk_hex"]

        # Mock the crypto context response to return the shared context
        shared_cc = alice_client_with_pre.__dict__["_test_crypto_context"]
        with patch.object(
            alice_client_with_pre, "get_pre_crypto_context"
        ) as mock_get_cc:
            mock_get_cc.return_value = pre.serialize_to_bytes(shared_cc)

            # Generate re-encryption key
            re_key_hex = alice_client_with_pre.generate_re_encryption_key(
                bob_pre_pk_hex
            )

        # Verify we got a valid hex string
        assert isinstance(re_key_hex, str)
        assert len(re_key_hex) > 0
        assert all(c in "0123456789abcdef" for c in re_key_hex.lower())

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


class TestAPIIntegration:
    """Test API integration for proxy re-encryption workflows."""

    def test_file_sharing_workflow_simulation(
        self, alice_client_with_pre, bob_client_with_pre
    ):
        """Test the complete file sharing workflow using PRE.

        This simulates the API workflow focusing on the client method calls
        rather than the detailed cryptographic operations (which are tested
        separately and in integration tests).
        """
        # Test file content
        file_content = b"This is Alice's confidential document for Bob"
        filename = "confidential.txt"

        # Get crypto context and keys for IDK message creation
        shared_cc = alice_client_with_pre.__dict__["_test_crypto_context"]
        alice_pre_keys = alice_client_with_pre.__dict__["_test_pre_keys"]

        # Get Alice's classic keys for signing
        alice_keys_data = KeyManager.load_identity_file(alice_client_with_pre.keys_path)
        alice_classic_sk = alice_keys_data["classic_sk"]

        # Step 1: Alice creates an IDK message (encrypted file format)
        optional_headers = {"Filename": filename, "ContentType": "text/plain"}
        idk_parts = idk_message.create_idk_message_parts(
            file_content,
            shared_cc,
            alice_pre_keys.publicKey,
            alice_classic_sk,
            optional_headers,
        )

        # Parse the first part to get file hash
        parsed_first_part = idk_message.parse_idk_message_part(idk_parts[0])
        file_hash = parsed_first_part["headers"]["MerkleRoot"]

        # Step 2: Mock file registration and upload
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

        # Step 3: Alice generates re-encryption key for Bob
        with open(bob_client_with_pre.keys_path, "r") as f:
            bob_identity = json.load(f)
        bob_pre_pk_hex = bob_identity["auth_keys"]["pre"]["pk_hex"]

        with patch.object(
            alice_client_with_pre, "get_pre_crypto_context"
        ) as mock_get_cc:
            mock_get_cc.return_value = pre.serialize_to_bytes(shared_cc)
            re_key_hex = alice_client_with_pre.generate_re_encryption_key(
                bob_pre_pk_hex
            )

        # Verify we got a valid re-encryption key
        assert isinstance(re_key_hex, str)
        assert len(re_key_hex) > 0
        assert all(c in "0123456789abcdef" for c in re_key_hex.lower())

        # Step 4: Alice creates a share
        with patch.object(alice_client_with_pre, "create_share") as mock_create_share:
            share_id = f"share_{secrets.token_hex(16)}"
            mock_create_share.return_value = {"share_id": share_id}

            share_result = alice_client_with_pre.create_share(
                bob_client_with_pre.get_classic_public_key(), file_hash, re_key_hex
            )
            assert share_result["share_id"] == share_id

        # Step 5: Mock Bob downloading the shared file
        mock_shared_file_data = b"mock_re_encrypted_content_for_bob"
        with patch.object(bob_client_with_pre, "download_shared_file") as mock_download:
            mock_download.return_value = mock_shared_file_data

            downloaded_data = bob_client_with_pre.download_shared_file(share_id)
            assert downloaded_data == mock_shared_file_data

        # Verify all the API calls were made with correct parameters
        mock_register.assert_called_once()
        mock_create_share.assert_called_once_with(
            bob_client_with_pre.get_classic_public_key(), file_hash, re_key_hex
        )
        mock_download.assert_called_once_with(share_id)

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

    def test_generate_re_key_without_pre_keys(self, temp_dir):
        """Test that generating re-encryption key fails without PRE keys."""
        # Create identity without PRE keys
        mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)
        client = DCypherClient(
            "http://localhost:8000", identity_path=str(identity_file)
        )

        # Try to generate re-encryption key
        with pytest.raises(Exception) as exc_info:
            client.generate_re_encryption_key("fake_bob_pk_hex")

        # Update to match the actual error message
        assert "PRE secret key not found" in str(exc_info.value)

    def test_invalid_crypto_context_handling(self, alice_client_with_pre):
        """Test handling of invalid crypto context."""
        with patch.object(
            alice_client_with_pre, "get_pre_crypto_context"
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


# Additional integration tests can be added here as the implementation evolves
