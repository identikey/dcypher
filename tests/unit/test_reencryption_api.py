import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

from src.lib.api_client import DCypherClient
from src.lib.key_manager import KeyManager
from src.app_state import get_app_state


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def alice_client(temp_dir):
    """Create Alice's client with PRE capabilities."""
    # Create identity file
    mnemonic, identity_file = KeyManager.create_identity_file("alice", temp_dir)

    # Create client
    client = DCypherClient("http://localhost:8000", identity_path=str(identity_file))

    # Initialize PRE capabilities
    with patch.object(client, "get_pre_crypto_context") as mock_get_cc:
        # Mock the crypto context response
        from src.lib import pre

        cc = pre.create_crypto_context()
        pre.generate_keys(cc)  # Initialize context
        mock_get_cc.return_value = pre.serialize_to_bytes(cc)

        client.initialize_pre_for_identity()

    return client


@pytest.fixture
def bob_client(temp_dir):
    """Create Bob's client with PRE capabilities."""
    # Create identity file
    mnemonic, identity_file = KeyManager.create_identity_file("bob", temp_dir)

    # Create client
    client = DCypherClient("http://localhost:8000", identity_path=str(identity_file))

    # Initialize PRE capabilities
    with patch.object(client, "get_pre_crypto_context") as mock_get_cc:
        # Mock the crypto context response
        from src.lib import pre

        cc = pre.create_crypto_context()
        pre.generate_keys(cc)  # Initialize context
        mock_get_cc.return_value = pre.serialize_to_bytes(cc)

        client.initialize_pre_for_identity()

    return client


def test_initialize_pre_for_identity(temp_dir):
    """Test PRE initialization for identity files."""
    # Create identity file
    mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)

    # Create client
    client = DCypherClient("http://localhost:8000", identity_path=str(identity_file))

    # Mock the crypto context response
    with patch.object(client, "get_pre_crypto_context") as mock_get_cc:
        from src.lib import pre

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


def test_generate_re_encryption_key(alice_client, bob_client):
    """Test generating a re-encryption key from Alice to Bob."""
    # Get Bob's PRE public key
    with open(bob_client.keys_path, "r") as f:
        bob_identity = json.load(f)
    bob_pre_pk_hex = bob_identity["auth_keys"]["pre"]["pk_hex"]

    # Mock the crypto context response
    with patch.object(alice_client, "get_pre_crypto_context") as mock_get_cc:
        from src.lib import pre

        cc = pre.create_crypto_context()
        pre.generate_keys(cc)  # Initialize context
        mock_get_cc.return_value = pre.serialize_to_bytes(cc)

        # Generate re-encryption key
        re_key_hex = alice_client.generate_re_encryption_key(bob_pre_pk_hex)

    # Verify we got a valid hex string
    assert isinstance(re_key_hex, str)
    assert len(re_key_hex) > 0
    assert all(c in "0123456789abcdef" for c in re_key_hex.lower())


def test_create_account_with_pre_key(temp_dir):
    """Test that account creation includes PRE public key if available."""
    # Create identity with PRE keys
    mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)

    # Initialize PRE for the identity
    with patch("src.lib.api_client.requests.get") as mock_get:
        from src.lib import pre

        cc = pre.create_crypto_context()
        pre.generate_keys(cc)  # Initialize context
        mock_get.return_value.content = pre.serialize_to_bytes(cc)

        KeyManager.add_pre_keys_to_identity(identity_file, pre.serialize_to_bytes(cc))

    # Create client
    client = DCypherClient("http://localhost:8000", identity_path=str(identity_file))

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
            {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in keys_data["pq_keys"]
        ]

        # Create account
        client.create_account(pk_classic_hex, pq_keys)

        # Verify the request included PRE public key
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert "pre_public_key_hex" in payload
        assert len(payload["pre_public_key_hex"]) > 0


def test_key_manager_add_pre_keys_to_identity(temp_dir):
    """Test adding PRE keys to an existing identity file."""
    # Create identity file
    mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)

    # Verify initial state (empty PRE section)
    with open(identity_file, "r") as f:
        identity_data = json.load(f)
    assert identity_data["auth_keys"]["pre"] == {}

    # Create crypto context
    from src.lib import pre

    cc = pre.create_crypto_context()
    pre.generate_keys(cc)  # Initialize context
    cc_bytes = pre.serialize_to_bytes(cc)

    # Add PRE keys
    KeyManager.add_pre_keys_to_identity(identity_file, cc_bytes)

    # Verify PRE keys were added
    with open(identity_file, "r") as f:
        updated_identity = json.load(f)

    assert "pk_hex" in updated_identity["auth_keys"]["pre"]
    assert "sk_hex" in updated_identity["auth_keys"]["pre"]
    assert len(updated_identity["auth_keys"]["pre"]["pk_hex"]) > 0
    assert len(updated_identity["auth_keys"]["pre"]["sk_hex"]) > 0


def test_pre_workflow_integration():
    """Test the complete PRE workflow."""
    from src.lib import pre

    # Create crypto context
    cc = pre.create_crypto_context()
    pre.generate_keys(cc)

    # Generate keys for Alice and Bob
    alice_keys = pre.generate_keys(cc)
    bob_keys = pre.generate_keys(cc)

    # Alice creates a re-encryption key for Bob
    re_key = pre.generate_re_encryption_key(
        cc, alice_keys.secretKey, bob_keys.publicKey
    )

    # Test data
    test_data = b"This is Alice's secret file content"
    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(test_data, slot_count)

    # Alice encrypts the data
    alice_ciphertext = pre.encrypt(cc, alice_keys.publicKey, coeffs)

    # Server applies re-encryption
    bob_ciphertext = pre.re_encrypt(cc, re_key, alice_ciphertext)

    # Bob decrypts the re-encrypted data
    decrypted_coeffs = pre.decrypt(cc, bob_keys.secretKey, bob_ciphertext, len(coeffs))
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(test_data))

    # Verify the data is correct
    assert decrypted_data == test_data


def test_app_state_pre_methods():
    """Test the PRE-related methods in app state."""
    state = get_app_state()

    # Test adding PRE key
    test_pk = "test_public_key"
    test_pre_key = b"test_pre_key_bytes"

    state.add_pre_key(test_pk, test_pre_key)
    retrieved_key = state.get_pre_key(test_pk)
    assert retrieved_key == test_pre_key

    # Test adding share
    test_share_id = "test_share_123"
    test_share_data = {
        "from": "alice_pk",
        "to": "bob_pk",
        "file_hash": "file123",
        "re_encryption_key": b"re_key_bytes",
    }

    state.add_share(test_share_id, test_share_data)
    retrieved_share = state.get_share(test_share_id)
    assert retrieved_share == test_share_data

    # Test removing share
    state.remove_share(test_share_id)
    assert state.get_share(test_share_id) is None


# More tests will be added here as the implementation evolves.
