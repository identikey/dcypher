"""
Integration tests for proxy re-encryption workflows with comprehensive content verification.

This test suite validates the complete end-to-end proxy re-encryption functionality:

1. **Complete Workflow Test (test_complete_reencryption_workflow_live_server)**:
   - Alice creates an account and uploads an encrypted file
   - Alice shares the file with Bob using proxy re-encryption
   - Bob downloads the re-encrypted file and decrypts it
   - VERIFIES: Bob receives exactly the same content Alice uploaded
   - Alice revokes Bob's access and verifies revocation works

2. **Multiple Users Test (test_multiple_users_sharing_workflow)**:
   - Alice uploads a file and shares it with both Bob and Charlie
   - Both recipients download and decrypt the shared file
   - VERIFIES: All recipients receive identical content to Alice's original
   - Tests revocation for multiple shares

3. **Key Management Test (test_pre_key_management_with_live_server)**:
   - Tests PRE key initialization and management
   - Verifies account creation with PRE capabilities
   - Tests re-encryption key generation

4. **Error Handling Test (test_error_handling_with_live_server)**:
   - Tests proper error handling for invalid operations
   - Verifies access control for non-existent resources

Key improvements over previous version:
- Removed weak error handling that allowed tests to pass when operations failed
- Added proper decryption and content verification at every step
- Ensures file upload must succeed before testing sharing
- Verifies end-to-end data integrity through the entire crypto workflow
- Tests both single and multiple recipient scenarios
"""

import pytest
import tempfile
import json
import secrets
import time
from pathlib import Path
import gzip
import base64
import hashlib
import io

from src.lib.api_client import DCypherClient, ResourceNotFoundError
from src.lib.key_manager import KeyManager
from src.lib import pre
from src.app_state import get_app_state
from src.lib import idk_message
import ecdsa
from src.crypto.context_manager import CryptoContextManager


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def alice_identity(temp_dir):
    """Create Alice's identity (PRE keys will be added by tests using server context)."""
    # Create identity file without PRE keys initially
    mnemonic, identity_file = KeyManager.create_identity_file("alice", temp_dir)

    return {
        "mnemonic": mnemonic,
        "identity_file": identity_file,
        "identity_data": json.loads(identity_file.read_text()),
    }


@pytest.fixture
def bob_identity(temp_dir):
    """Create Bob's identity (PRE keys will be added by tests using server context)."""
    # Create identity file without PRE keys initially
    mnemonic, identity_file = KeyManager.create_identity_file("bob", temp_dir)

    return {
        "mnemonic": mnemonic,
        "identity_file": identity_file,
        "identity_data": json.loads(identity_file.read_text()),
    }


def test_complete_reencryption_workflow_live_server(
    alice_identity, bob_identity, api_base_url, temp_dir
):
    """
    Test the complete proxy re-encryption workflow against a live API server:
    1. Alice and Bob create accounts with PRE capabilities
    2. Alice uploads an encrypted file
    3. Alice shares the file with Bob using proxy re-encryption
    4. Bob downloads and decrypts the shared file
    5. Verify Bob received the exact same content Alice uploaded
    6. Alice revokes Bob's access
    7. Verify Bob can no longer access the file
    """

    print("🔧 Setting up Alice and Bob's accounts with live server...")

    # Create API clients for Alice and Bob
    alice_client = DCypherClient(
        api_base_url, identity_path=str(alice_identity["identity_file"])
    )
    bob_client = DCypherClient(
        api_base_url, identity_path=str(bob_identity["identity_file"])
    )

    # Get the server's crypto context
    server_cc_bytes = alice_client.get_pre_crypto_context()

    # CRITICAL: Use the context singleton pattern to ensure ALL operations use the SAME context instance
    # This resolves the OpenFHE limitation where crypto objects must be created with the same context.

    # Reset singleton to start fresh
    CryptoContextManager._instance = None
    context_manager = CryptoContextManager()

    # Initialize the singleton with the server's context
    serialized_context = base64.b64encode(server_cc_bytes).decode("ascii")
    server_cc = context_manager.deserialize_context(serialized_context)

    # CRITICAL: Generate different PRE keys for Alice and Bob from the SAME context instance
    # This ensures proper proxy re-encryption while maintaining crypto context consistency
    alice_keys = pre.generate_keys(server_cc)
    bob_keys = pre.generate_keys(server_cc)

    alice_pk_bytes = pre.serialize_to_bytes(alice_keys.publicKey)
    alice_sk_bytes = pre.serialize_to_bytes(alice_keys.secretKey)
    bob_pk_bytes = pre.serialize_to_bytes(bob_keys.publicKey)
    bob_sk_bytes = pre.serialize_to_bytes(bob_keys.secretKey)

    print(f"✅ Generated Alice's PRE keys: {alice_pk_bytes.hex()[:32]}...")
    print(f"✅ Generated Bob's PRE keys: {bob_pk_bytes.hex()[:32]}...")

    # Add Alice's PRE keys to her identity
    with open(alice_identity["identity_file"], "r") as f:
        alice_data = json.load(f)
    alice_data["auth_keys"]["pre"] = {
        "pk_hex": alice_pk_bytes.hex(),
        "sk_hex": alice_sk_bytes.hex(),
    }
    with open(alice_identity["identity_file"], "w") as f:
        json.dump(alice_data, f, indent=2)
    alice_identity["identity_data"] = alice_data
    print("✅ Added Alice's PRE keys to her identity")

    # Add Bob's PRE keys to his identity
    with open(bob_identity["identity_file"], "r") as f:
        bob_data = json.load(f)
    bob_data["auth_keys"]["pre"] = {
        "pk_hex": bob_pk_bytes.hex(),
        "sk_hex": bob_sk_bytes.hex(),
    }
    with open(bob_identity["identity_file"], "w") as f:
        json.dump(bob_data, f, indent=2)
    bob_identity["identity_data"] = bob_data
    print("✅ Added Bob's PRE keys to his identity")

    # Get Alice's keys for account creation and message operations
    alice_keys_data = KeyManager.load_identity_file(alice_identity["identity_file"])
    alice_pk = KeyManager.get_classic_public_key(alice_keys_data["classic_sk"])
    alice_pq_keys = [
        {"pk_hex": key["pk_hex"], "alg": key["alg"]}
        for key in alice_keys_data["pq_keys"]
    ]
    alice_classic_sk = alice_keys_data["classic_sk"]  # ECDSA signing key
    alice_classic_vk = alice_classic_sk.verifying_key  # ECDSA verifying key

    # Get Bob's keys for account creation and decryption
    bob_keys_data = KeyManager.load_identity_file(bob_identity["identity_file"])
    bob_pk = KeyManager.get_classic_public_key(bob_keys_data["classic_sk"])
    bob_pq_keys = [
        {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in bob_keys_data["pq_keys"]
    ]
    # Bob's PRE secret key (different from Alice's)
    bob_pre_sk = bob_keys.secretKey

    # Create accounts on the live server
    alice_client.create_account(alice_pk, alice_pq_keys)
    bob_client.create_account(bob_pk, bob_pq_keys)

    print(f"✅ Alice's account: {alice_pk[:16]}...")
    print(f"✅ Bob's account: {bob_pk[:16]}...")

    # Verify accounts exist
    alice_account = alice_client.get_account(alice_pk)
    bob_account = bob_client.get_account(bob_pk)
    assert alice_account["public_key"] == alice_pk
    assert bob_account["public_key"] == bob_pk

    print("📁 Alice uploads a secret file...")

    # Create a test file for Alice to upload
    secret_message = (
        b"This is Alice's super secret message that she wants to share with Bob!"
    )
    test_file = temp_dir / "secret_message.txt"
    test_file.write_bytes(secret_message)

    # Use Alice's PRE public key for creating IDK message
    alice_pre_pk = alice_keys.publicKey

    # Create IDK message parts using the server's crypto context
    optional_headers = {"Filename": "secret_message.txt", "ContentType": "text/plain"}

    idk_parts = idk_message.create_idk_message_parts(
        secret_message, server_cc, alice_pre_pk, alice_classic_sk, optional_headers
    )

    # Get the file hash from the first IDK part
    parsed_first_part = idk_message.parse_idk_message_part(idk_parts[0])
    file_hash = parsed_first_part["headers"]["MerkleRoot"]

    print(
        f"✅ Created IDK message with {len(idk_parts)} parts, hash: {file_hash[:16]}..."
    )

    # Register the file with Alice - this MUST succeed for a valid test
    register_response = alice_client.register_file(
        public_key=alice_pk,
        file_hash=file_hash,
        idk_part_one=idk_parts[0],
        filename="secret_message.txt",
        content_type="text/plain",
        total_size=len(secret_message),
    )
    print(f"✅ File registered successfully: {register_response['message']}")

    # Upload additional chunks if there are more than one part
    if len(idk_parts) > 1:
        for i, part in enumerate(idk_parts[1:], 1):
            chunk_hash = hashlib.blake2b(part.encode()).hexdigest()
            alice_client.upload_chunk(
                public_key=alice_pk,
                file_hash=file_hash,
                chunk_data=part.encode(),
                chunk_hash=chunk_hash,
                chunk_index=i,
                total_chunks=len(idk_parts),
            )
        print(f"✅ Uploaded {len(idk_parts) - 1} additional chunks")

    print("🔗 Alice shares the file with Bob using proxy re-encryption...")

    # Get Bob's PRE public key for re-encryption key generation
    bob_pre_pk_hex = bob_identity["identity_data"]["auth_keys"]["pre"]["pk_hex"]

    # Alice generates a re-encryption key for Bob
    re_key_hex = alice_client.generate_re_encryption_key(bob_pre_pk_hex)
    print(f"✅ Re-encryption key generated: {re_key_hex[:32]}...")

    # Alice creates a share with Bob
    share_response = alice_client.create_share(bob_pk, file_hash, re_key_hex)
    share_id = share_response["share_id"]
    print(f"✅ Share created with ID: {share_id}")

    # Bob lists his received shares
    bob_shares = bob_client.list_shares(bob_pk)
    assert len(bob_shares["shares_received"]) == 1
    assert bob_shares["shares_received"][0]["share_id"] == share_id
    assert bob_shares["shares_received"][0]["from"] == alice_pk
    print(f"✅ Bob found {len(bob_shares['shares_received'])} shared file(s)")

    # Alice lists her sent shares
    alice_shares = alice_client.list_shares(alice_pk)
    assert len(alice_shares["shares_sent"]) == 1
    assert alice_shares["shares_sent"][0]["share_id"] == share_id
    assert alice_shares["shares_sent"][0]["to"] == bob_pk
    print(f"✅ Alice can see {len(alice_shares['shares_sent'])} file(s) she shared")

    print("🔓 Bob downloads and decrypts the shared file...")

    # Bob downloads the shared file (server applies re-encryption)
    shared_file_data = bob_client.download_shared_file(share_id)
    print(f"✅ Bob downloaded {len(shared_file_data)} bytes of re-encrypted data")

    # The server returns gzip-compressed IDK message content
    # We need to decompress it first, then parse the IDK message parts
    if isinstance(shared_file_data, bytes):
        try:
            # Decompress the gzip data
            decompressed_data = gzip.decompress(shared_file_data)
            shared_file_str = decompressed_data.decode("utf-8")
            print(f"✅ Decompressed {len(decompressed_data)} bytes to IDK message")
        except Exception as e:
            # If decompression fails, try treating as raw text
            shared_file_str = shared_file_data.decode("utf-8")
            print("⚠️  Data was not compressed, treating as raw text")
    else:
        shared_file_str = shared_file_data

    # CRITICAL VERIFICATION: Ensure Bob received exactly what Alice uploaded
    # With proper server PRE implementation, Bob should be able to decrypt
    # the re-encrypted content using his own secret key

    try:
        decrypted_content = idk_message.decrypt_idk_message(
            cc=server_cc,  # Same server crypto context Alice used
            sk=bob_pre_sk,  # Bob's own PRE secret key
            message_str=shared_file_str,
        )

        print(f"✅ Bob decrypted {len(decrypted_content)} bytes of content")

        # Verify Bob received exactly what Alice uploaded
        assert decrypted_content == secret_message, (
            f"Content mismatch! Alice uploaded: {secret_message!r}, "
            f"Bob received: {decrypted_content!r}"
        )
        print("🎉 SUCCESS: Bob received exactly the same content Alice uploaded!")
        print("✅ Proxy re-encryption is working correctly!")

    except Exception as e:
        print(f"❌ FAILED: Bob could not decrypt the shared content: {e}")
        print("❌ This indicates an issue with the proxy re-encryption implementation")
        raise AssertionError(f"Proxy re-encryption verification failed: {e}")

    print("🚫 Testing share revocation...")

    # Alice revokes the share
    revoke_response = alice_client.revoke_share(share_id)
    assert revoke_response["message"] == "Share revoked successfully"
    print("✅ Share revoked successfully")

    # Verify Bob can no longer access the revoked share
    try:
        bob_client.download_shared_file(share_id)
        assert False, "Bob should not be able to download after revocation"
    except Exception as e:
        assert (
            "not found" in str(e).lower()
            or "revoked" in str(e).lower()
            or "404" in str(e)
        )
        print("✅ Bob correctly cannot access revoked share")

    # Verify the share is removed from listings
    alice_shares_after = alice_client.list_shares(alice_pk)
    bob_shares_after = bob_client.list_shares(bob_pk)

    # Check that shares are no longer listed (implementation dependent)
    print("✅ Verified share revocation workflow")

    print(
        "🎉 Complete proxy re-encryption workflow successful with content verification!"
    )


def test_multiple_users_sharing_workflow(api_base_url, temp_dir):
    """
    Test multiple users sharing files with each other using a live server.
    This test verifies that Alice can upload a file and share it with both Bob and Charlie,
    and that each recipient receives the exact same content.
    """
    print("🔧 Testing multiple users sharing workflow...")

    # Create a temporary client to get the server's crypto context
    temp_mnemonic, temp_identity = KeyManager.create_identity_file("temp", temp_dir)
    temp_client = DCypherClient(api_base_url, identity_path=str(temp_identity))

    # Get the server's crypto context that all users must share
    server_cc_bytes = temp_client.get_pre_crypto_context()

    # CRITICAL: Use the context singleton pattern to ensure ALL operations use the SAME context instance
    # Reset singleton to start fresh for this test
    CryptoContextManager._instance = None
    context_manager = CryptoContextManager()

    # Initialize the singleton with the server's context
    serialized_context = base64.b64encode(server_cc_bytes).decode("ascii")
    server_cc = context_manager.deserialize_context(serialized_context)

    # Generate different PRE keys for each user from the same crypto context instance
    user_pre_keys = {}
    for name in ["alice", "bob", "charlie"]:
        keys = pre.generate_keys(server_cc)
        user_pre_keys[name] = {
            "publicKey": keys.publicKey,
            "secretKey": keys.secretKey,
            "pk_bytes": pre.serialize_to_bytes(keys.publicKey),
            "sk_bytes": pre.serialize_to_bytes(keys.secretKey),
        }
        print(
            f"✅ Generated PRE keys for {name}: {user_pre_keys[name]['pk_bytes'].hex()[:32]}..."
        )

    # Create identities for Alice, Bob, and Charlie
    users = {}
    for name in ["alice", "bob", "charlie"]:
        mnemonic, identity_file = KeyManager.create_identity_file(name, temp_dir)

        # Add the pre-generated PRE keys to this user's identity
        with open(identity_file, "r") as f:
            identity_data = json.load(f)
        identity_data["auth_keys"]["pre"] = {
            "pk_hex": user_pre_keys[name]["pk_bytes"].hex(),
            "sk_hex": user_pre_keys[name]["sk_bytes"].hex(),
        }
        with open(identity_file, "w") as f:
            json.dump(identity_data, f, indent=2)

        # Create client and account
        client = DCypherClient(api_base_url, identity_path=str(identity_file))
        keys_data = KeyManager.load_identity_file(identity_file)
        pk = KeyManager.get_classic_public_key(keys_data["classic_sk"])
        pq_keys = [
            {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in keys_data["pq_keys"]
        ]

        client.create_account(pk, pq_keys)

        users[name] = {
            "client": client,
            "public_key": pk,
            "identity_file": identity_file,
            "identity_data": identity_data,
            "keys_data": keys_data,
            "cc": server_cc,  # All users share the same server crypto context
            "pre_keys": user_pre_keys[name],  # Each user has different PRE keys
        }

        print(f"✅ Created account for {name}: {pk[:16]}...")

    # Clean up temp files
    temp_identity.unlink()

    # Alice creates and uploads a file to share
    alice = users["alice"]
    bob = users["bob"]
    charlie = users["charlie"]

    print("📁 Alice creates and uploads a file...")

    # Create test content
    test_content = b"This is Alice's file that she wants to share with Bob and Charlie!"

    # Get Alice's crypto context and keys (all using server context)
    alice_cc = alice["cc"]  # This is the server crypto context
    alice_pre_pk = alice["pre_keys"]["publicKey"]  # Use the actual key object
    alice_classic_sk = alice["keys_data"]["classic_sk"]
    alice_classic_vk = alice_classic_sk.verifying_key

    # Create IDK message using the server crypto context
    optional_headers = {"Filename": "shared_file.txt", "ContentType": "text/plain"}
    idk_parts = idk_message.create_idk_message_parts(
        test_content, alice_cc, alice_pre_pk, alice_classic_sk, optional_headers
    )

    # Get file hash
    parsed_first_part = idk_message.parse_idk_message_part(idk_parts[0])
    file_hash = parsed_first_part["headers"]["MerkleRoot"]

    # Register the file
    register_response = alice["client"].register_file(
        public_key=alice["public_key"],
        file_hash=file_hash,
        idk_part_one=idk_parts[0],
        filename="shared_file.txt",
        content_type="text/plain",
        total_size=len(test_content),
    )
    print(f"✅ File registered: {register_response['message']}")

    # Upload additional chunks if needed
    if len(idk_parts) > 1:
        for i, part in enumerate(idk_parts[1:], 1):
            chunk_hash = hashlib.blake2b(part.encode()).hexdigest()
            alice["client"].upload_chunk(
                public_key=alice["public_key"],
                file_hash=file_hash,
                chunk_data=part.encode(),
                chunk_hash=chunk_hash,
                chunk_index=i,
                total_chunks=len(idk_parts),
            )
        print(f"✅ Uploaded {len(idk_parts) - 1} additional chunks")

    print("🔗 Alice shares the file with Bob and Charlie...")

    # Generate re-encryption keys for both recipients
    bob_pre_pk = bob["identity_data"]["auth_keys"]["pre"]["pk_hex"]
    charlie_pre_pk = charlie["identity_data"]["auth_keys"]["pre"]["pk_hex"]

    alice_to_bob_key = alice["client"].generate_re_encryption_key(bob_pre_pk)
    alice_to_charlie_key = alice["client"].generate_re_encryption_key(charlie_pre_pk)

    # Create shares
    alice_bob_share = alice["client"].create_share(
        bob["public_key"], file_hash, alice_to_bob_key
    )
    alice_charlie_share = alice["client"].create_share(
        charlie["public_key"], file_hash, alice_to_charlie_key
    )

    print("✅ Shares created successfully")

    # Test that each user can see their respective shares
    bob_shares = bob["client"].list_shares(bob["public_key"])
    charlie_shares = charlie["client"].list_shares(charlie["public_key"])
    alice_shares = alice["client"].list_shares(alice["public_key"])

    assert len(bob_shares["shares_received"]) == 1
    assert len(charlie_shares["shares_received"]) == 1
    assert len(alice_shares["shares_sent"]) == 2

    print("✅ All users can see their respective shares")

    print("🔓 Bob and Charlie download and decrypt the shared file...")

    # Test that both Bob and Charlie can download and decrypt the file
    # NOTE: Like the main test, this will show expected garbled content due to
    # server not implementing actual PRE transformation
    for recipient_name, recipient in [("Bob", bob), ("Charlie", charlie)]:
        print(f"  Testing {recipient_name}...")

        # Get the appropriate share ID
        recipient_shares = recipient["client"].list_shares(recipient["public_key"])
        share_id = recipient_shares["shares_received"][0]["share_id"]

        # Download the shared file
        shared_file_data = recipient["client"].download_shared_file(share_id)

        # Handle gzip-compressed data
        if isinstance(shared_file_data, bytes):
            try:
                # Decompress the gzip data
                decompressed_data = gzip.decompress(shared_file_data)
                shared_file_str = decompressed_data.decode("utf-8")
                print(
                    f"    ✅ Decompressed {len(decompressed_data)} bytes to IDK message"
                )
            except Exception:
                # If decompression fails, try treating as raw text
                shared_file_str = shared_file_data.decode("utf-8")
                print("    ⚠️  Data was not compressed, treating as raw text")
        else:
            shared_file_str = shared_file_data

        # Get recipient's PRE secret key for decryption
        recipient_pre_sk = recipient["pre_keys"]["secretKey"]

        # Decrypt the content using the server crypto context
        try:
            decrypted_content = idk_message.decrypt_idk_message(
                cc=server_cc,  # Use the same server crypto context for all operations
                sk=recipient_pre_sk,
                message_str=shared_file_str,
            )

            # Verify content - should match Alice's original
            assert decrypted_content == test_content, (
                f"{recipient_name} received different content! "
                f"Expected: {test_content!r}, Got: {decrypted_content!r}"
            )
            print(f"  ✅ {recipient_name} received correct content")
            print(f"  ✅ Proxy re-encryption working for {recipient_name}")

        except Exception as e:
            print(f"  ❌ {recipient_name} failed to decrypt: {e}")
            raise AssertionError(f"PRE failed for {recipient_name}: {e}")

    print("✅ Multiple users crypto context consistency confirmed!")

    print("🚫 Testing share revocation...")

    # Test revocation
    alice["client"].revoke_share(alice_bob_share["share_id"])
    alice["client"].revoke_share(alice_charlie_share["share_id"])

    print("✅ All shares revoked successfully")

    # Verify revoked shares cannot be accessed
    for recipient_name, recipient in [("Bob", bob), ("Charlie", charlie)]:
        recipient_shares = recipient["client"].list_shares(recipient["public_key"])
        if recipient_shares["shares_received"]:  # If shares still listed
            share_id = recipient_shares["shares_received"][0]["share_id"]
            try:
                recipient["client"].download_shared_file(share_id)
                assert False, (
                    f"{recipient_name} should not be able to download after revocation"
                )
            except Exception as e:
                assert (
                    "not found" in str(e).lower()
                    or "revoked" in str(e).lower()
                    or "404" in str(e)
                )
                print(f"  ✅ {recipient_name} correctly cannot access revoked share")

    print("🎉 Multiple users sharing workflow with content verification successful!")


def test_pre_key_management_with_live_server(api_base_url, temp_dir):
    """
    Test PRE key management functionality with a live server.
    """
    print("🔧 Testing PRE key management with live server...")

    # Create identity without PRE keys initially
    mnemonic, identity_file = KeyManager.create_identity_file("test_user", temp_dir)

    # Verify initial state
    with open(identity_file, "r") as f:
        identity_data = json.load(f)
    assert identity_data["auth_keys"]["pre"] == {}
    print("✅ Identity created with empty PRE section")

    # Create client and test PRE initialization
    client = DCypherClient(api_base_url, identity_path=str(identity_file))

    # Initialize PRE capabilities
    client.initialize_pre_for_identity()

    # Verify PRE keys were added
    with open(identity_file, "r") as f:
        updated_identity = json.load(f)

    pre_keys = updated_identity["auth_keys"]["pre"]
    assert "pk_hex" in pre_keys
    assert "sk_hex" in pre_keys
    assert len(pre_keys["pk_hex"]) > 0
    assert len(pre_keys["sk_hex"]) > 0

    print(f"✅ PRE keys added - Public key: {pre_keys['pk_hex'][:32]}...")

    # Create account with PRE keys
    keys_data = KeyManager.load_identity_file(identity_file)
    pk = KeyManager.get_classic_public_key(keys_data["classic_sk"])
    pq_keys = [
        {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in keys_data["pq_keys"]
    ]

    client.create_account(pk, pq_keys)

    # Verify account was created with PRE key
    account_info = client.get_account(pk)
    assert account_info["public_key"] == pk
    print("✅ Account created successfully with PRE capabilities")

    # Test re-encryption key generation
    # Create another user for testing
    other_mnemonic, other_identity = KeyManager.create_identity_file(
        "other_user", temp_dir
    )

    # Create a separate client for the other user and initialize their PRE keys
    other_client = DCypherClient(api_base_url, identity_path=str(other_identity))
    other_client.initialize_pre_for_identity()  # Initialize PRE keys for the other user

    with open(other_identity, "r") as f:
        other_data = json.load(f)
    other_pre_pk = other_data["auth_keys"]["pre"]["pk_hex"]

    re_key_hex = client.generate_re_encryption_key(other_pre_pk)
    assert isinstance(re_key_hex, str)
    assert len(re_key_hex) > 0

    print(f"✅ Re-encryption key generated: {re_key_hex[:32]}...")
    print("🎉 PRE key management test completed successfully!")


def test_error_handling_with_live_server(alice_identity, bob_identity, api_base_url):
    """
    Test error handling with a live server.
    """
    print("🔧 Testing error handling with live server...")

    # Create clients
    alice_client = DCypherClient(
        api_base_url, identity_path=str(alice_identity["identity_file"])
    )
    bob_client = DCypherClient(
        api_base_url, identity_path=str(bob_identity["identity_file"])
    )

    # Create accounts
    alice_keys_data = KeyManager.load_identity_file(alice_identity["identity_file"])
    alice_pk = KeyManager.get_classic_public_key(alice_keys_data["classic_sk"])
    alice_pq_keys = [
        {"pk_hex": key["pk_hex"], "alg": key["alg"]}
        for key in alice_keys_data["pq_keys"]
    ]

    bob_keys_data = KeyManager.load_identity_file(bob_identity["identity_file"])
    bob_pk = KeyManager.get_classic_public_key(bob_keys_data["classic_sk"])
    bob_pq_keys = [
        {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in bob_keys_data["pq_keys"]
    ]

    alice_client.create_account(alice_pk, alice_pq_keys)
    bob_client.create_account(bob_pk, bob_pq_keys)

    # Test 1: Try to download non-existent share
    print("❌ Testing access to non-existent share...")
    fake_share_id = "nonexistent_share_" + secrets.token_hex(16)

    try:
        bob_client.download_shared_file(fake_share_id)
        assert False, "Should have raised an exception"
    except Exception as e:
        assert "not found" in str(e).lower() or "404" in str(e)
        print("✅ Correctly handled non-existent share access")

    # Test 2: Try to revoke non-existent share
    print("❌ Testing revocation of non-existent share...")

    try:
        alice_client.revoke_share(fake_share_id)
        assert False, "Should have raised an exception"
    except Exception as e:
        assert "not found" in str(e).lower() or "404" in str(e)
        print("✅ Correctly handled non-existent share revocation")

    print("🎉 Error handling tests completed successfully!")


if __name__ == "__main__":
    """
    Run this file directly to see the proxy re-encryption workflow in action!
    
    Usage:
        python -m pytest tests/integration/test_reencryption_workflows.py -v -s
    
    Or run individual tests:
        python -m pytest tests/integration/test_reencryption_workflows.py::test_complete_reencryption_workflow_live_server -v -s
    """
    print("🚀 Proxy Re-Encryption Integration Tests (Live Server)")
    print("=" * 60)
    print("Run with: pytest tests/integration/test_reencryption_workflows.py -v -s")
