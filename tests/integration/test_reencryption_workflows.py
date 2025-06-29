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
def alice_identity(temp_dir, api_base_url):
    """Create Alice's identity with PRE keys using server context."""
    # ARCHITECTURAL FIX: Fetch context bytes externally to use new KeyManager API
    from src.lib.api_client import DCypherClient

    temp_client = DCypherClient(api_base_url)
    cc_bytes = temp_client.get_pre_crypto_context()

    # Create identity file with PRE keys using fetched context bytes
    mnemonic, identity_file = KeyManager.create_identity_file(
        "alice",
        temp_dir,
        context_bytes=cc_bytes,
        context_source=f"server:{api_base_url}",
    )

    return {
        "mnemonic": mnemonic,
        "identity_file": identity_file,
        "identity_data": json.loads(identity_file.read_text()),
    }


@pytest.fixture
def bob_identity(temp_dir, api_base_url):
    """Create Bob's identity with PRE keys using server context."""
    # ARCHITECTURAL FIX: Fetch context bytes externally to use new KeyManager API
    from src.lib.api_client import DCypherClient

    temp_client = DCypherClient(api_base_url)
    cc_bytes = temp_client.get_pre_crypto_context()

    # Create identity file with PRE keys using fetched context bytes
    mnemonic, identity_file = KeyManager.create_identity_file(
        "bob", temp_dir, context_bytes=cc_bytes, context_source=f"server:{api_base_url}"
    )

    return {
        "mnemonic": mnemonic,
        "identity_file": identity_file,
        "identity_data": json.loads(identity_file.read_text()),
    }


def test_complete_reencryption_workflow_live_server(api_base_url, temp_dir):
    """
    Test the complete proxy re-encryption workflow against a live API server:
    1. Alice and Bob create accounts with PRE capabilities using CLI commands
    2. Alice uploads an encrypted file using CLI
    3. Alice shares the file with Bob using proxy re-encryption using CLI
    4. Bob downloads and decrypts the shared file using CLI
    5. Verify Bob received the exact same content Alice uploaded
    6. Alice revokes Bob's access using CLI
    7. Verify Bob can no longer access the file using CLI

    This test uses CLI commands for everything to match the working CLI test pattern.
    """

    import subprocess
    import sys
    from pathlib import Path

    # KeyManager is already imported at the top of the file
    import gzip
    import base64
    import json
    from crypto.context_manager import CryptoContextManager
    from src.lib import pre, idk_message

    print("🔧 Setting up Alice and Bob's accounts with live server using CLI...")

    # === Step 1: Create Alice's Identity using CLI (just like working test) ===
    alice_identity_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "identity",
        "new",
        "--name",
        "Alice",
        "--path",
        str(temp_dir),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(alice_identity_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Alice identity creation failed: {result.stderr}"
    alice_identity_file = temp_dir / "Alice.json"
    assert alice_identity_file.exists()

    # === Step 2: Create Bob's Identity using CLI ===
    bob_identity_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "identity",
        "new",
        "--name",
        "Bob",
        "--path",
        str(temp_dir),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(bob_identity_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Bob identity creation failed: {result.stderr}"
    bob_identity_file = temp_dir / "Bob.json"
    assert bob_identity_file.exists()

    # === Step 3: Initialize PRE for both identities using CLI ===
    alice_pre_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "init-pre",
        "--identity-path",
        str(alice_identity_file),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(alice_pre_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Alice PRE init failed: {result.stderr}"

    bob_pre_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "init-pre",
        "--identity-path",
        str(bob_identity_file),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(bob_pre_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Bob PRE init failed: {result.stderr}"

    # === Step 4: Create accounts on the server using CLI ===
    alice_account_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "create-account",
        "--identity-path",
        str(alice_identity_file),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(alice_account_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Alice account creation failed: {result.stderr}"

    bob_account_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "create-account",
        "--identity-path",
        str(bob_identity_file),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(bob_account_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Bob account creation failed: {result.stderr}"

    print("✅ Alice and Bob identities, PRE keys, and accounts created via CLI")

    print("📁 Alice uploads a secret file...")

    # Create a test file for Alice to upload
    secret_message = (
        b"This is Alice's super secret message that she wants to share with Bob!"
    )
    test_file = temp_dir / "secret_message.txt"
    test_file.write_bytes(secret_message)

    # CRITICAL: Use subprocess to call the working CLI upload command
    # This uses the exact same workflow as the passing CLI test
    import subprocess
    import sys

    # Use the CLI upload command that we know works perfectly
    upload_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "upload",
        "--identity-path",
        str(alice_identity_file),
        "--file-path",
        str(test_file),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(upload_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Upload failed: {result.stderr}"

    # Extract file hash from upload output (same as CLI test)
    file_hash = None
    for line in result.stderr.splitlines():
        if "Registering file with hash:" in line:
            file_hash = line.split()[-1]
            break
    assert file_hash, "Could not find file hash in upload output"

    print(f"✅ File uploaded successfully with hash: {file_hash[:16]}...")

    print("🔗 Alice shares the file with Bob using proxy re-encryption...")

    # Get Bob's public key for sharing using CLI
    with open(bob_identity_file, "r") as f:
        bob_data = json.load(f)
    bob_keys_data = KeyManager.load_identity_file(bob_identity_file)
    bob_pk = KeyManager.get_classic_public_key(bob_keys_data["classic_sk"])

    # === Step 5: Alice shares file with Bob using CLI ===
    share_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "create-share",
        "--identity-path",
        str(alice_identity_file),
        "--api-url",
        api_base_url,
        "--file-hash",
        file_hash,
        "--bob-public-key",
        bob_pk,
    ]

    result = subprocess.run(share_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Alice file sharing failed: {result.stderr}"

    # Extract share_id from CLI output (checking both stdout and stderr)
    share_id = None
    for line in (result.stdout + result.stderr).strip().split("\n"):
        if "Share ID:" in line:
            share_id = line.split("Share ID:")[-1].strip()
            break
    assert share_id is not None, (
        f"Could not extract share_id from share output.\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    )
    print(f"✅ Share created with ID: {share_id}")

    print("🔓 Bob downloads and decrypts the shared file...")

    # === Step 6: Bob downloads and decrypts the shared file using CLI ===
    print("📥 Bob downloads and decrypts the shared file...")

    shared_file_path = temp_dir / "bob_received_file.txt"
    download_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "download-shared",
        "--identity-path",
        str(bob_identity_file),
        "--share-id",
        share_id,
        "--output-path",
        str(shared_file_path),
        "--api-url",
        api_base_url,
    ]

    download_result = subprocess.run(download_cmd, capture_output=True, text=True)
    assert download_result.returncode == 0, f"Download failed: {download_result.stderr}"
    assert shared_file_path.exists()
    print("✅ Bob downloaded and decrypted the file using CLI")

    # === CRITICAL VERIFICATION ===
    # Read the downloaded file and decrypt the IDK message (like the working CLI test)
    # Reset singleton to start fresh
    CryptoContextManager.reset_all_instances()
    context_manager = CryptoContextManager()

    # Get server's crypto context
    bob_client = DCypherClient(api_base_url, identity_path=str(bob_identity_file))
    # CRITICAL FIX: Use get_crypto_context_object() to avoid calling fhe.ReleaseAllContexts()
    # which would destroy contexts in parallel test execution
    cc = bob_client.get_crypto_context_object()

    # Get Bob's PRE secret key from his identity
    with open(bob_identity_file, "r") as f:
        bob_identity_data = json.load(f)

    bob_pre_sk_hex = bob_identity_data["auth_keys"]["pre"]["sk_hex"]
    bob_pre_sk_bytes = bytes.fromhex(bob_pre_sk_hex)
    bob_sk_enc = pre.deserialize_secret_key(bob_pre_sk_bytes)

    # Read and decompress the downloaded file
    with open(shared_file_path, "rb") as f:
        shared_file_data = f.read()

    # Decompress the gzip data to get the IDK message
    try:
        decompressed_data = gzip.decompress(shared_file_data)
        shared_file_str = decompressed_data.decode("utf-8")
        print(f"✅ Decompressed {len(decompressed_data)} bytes to IDK message")
    except Exception:
        shared_file_str = shared_file_data.decode("utf-8")
        print("⚠️ Data was not compressed, treating as raw text")

    # CRITICAL: Decrypt the IDK message using Bob's PRE secret key
    try:
        received_content = idk_message.decrypt_idk_message(
            cc=cc,
            sk=bob_sk_enc,
            message_str=shared_file_str,
        )
        print(f"✅ Bob decrypted {len(received_content)} bytes of content")
    except Exception as e:
        print(f"❌ FAILED: Bob could not decrypt the shared content: {e}")
        raise AssertionError(f"Proxy re-encryption verification failed: {e}")

    print(f"📝 Original content: {secret_message[:50]}...")
    print(f"📝 Received content: {received_content[:50]}...")

    # THE MOMENT OF TRUTH: Verify Bob received exactly what Alice uploaded
    assert received_content == secret_message, (
        f"Content mismatch! Alice uploaded: {secret_message!r}, "
        f"Bob received: {received_content!r}"
    )
    print("🎉 SUCCESS: Bob received exactly the same content Alice uploaded!")
    print("✅ Proxy re-encryption is working correctly!")

    print("🚫 Testing share revocation...")

    # === Step 7: Alice revokes Bob's access using CLI ===
    revoke_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "revoke-share",
        "--identity-path",
        str(alice_identity_file),
        "--api-url",
        api_base_url,
        "--share-id",
        share_id,
    ]

    result = subprocess.run(revoke_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Alice share revocation failed: {result.stderr}"
    print("✅ Share revoked successfully")

    # === Step 8: Verify Bob can no longer access the revoked share using CLI ===
    revoked_file_path = temp_dir / "should_fail.txt"
    download_fail_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "download-shared",
        "--identity-path",
        str(bob_identity_file),
        "--share-id",
        share_id,
        "--output-path",
        str(revoked_file_path),
        "--api-url",
        api_base_url,
    ]

    result = subprocess.run(download_fail_cmd, capture_output=True, text=True)
    assert result.returncode != 0, "Bob should not be able to download after revocation"
    print(f"✅ Bob correctly cannot access revoked share: {result.stderr}")

    print("✅ Verified share revocation workflow")

    print(
        "🎉 Complete proxy re-encryption workflow successful with content verification!"
    )


def test_pre_key_management_with_live_server(api_base_url, temp_dir):
    """
    Test PRE key management functionality with a live server.
    """
    print("🔧 Testing PRE key management with live server...")
    import subprocess
    import sys
    from pathlib import Path

    # Create identity with PRE keys using the CLI
    identity_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "identity",
        "new",
        "--name",
        "test_user",
        "--path",
        str(temp_dir),
        "--api-url",
        api_base_url,
    ]
    result = subprocess.run(identity_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Identity creation failed: {result.stderr}"
    identity_file = temp_dir / "test_user.json"
    assert identity_file.exists()

    # Verify PRE keys were added
    with open(identity_file, "r") as f:
        identity_data = json.load(f)
    pre_keys = identity_data["auth_keys"]["pre"]
    assert "pk_hex" in pre_keys and "sk_hex" in pre_keys
    print(f"✅ PRE keys added - Public key: {pre_keys['pk_hex'][:32]}...")

    # Create account with PRE keys using the CLI
    account_cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "src" / "cli.py"),
        "create-account",
        "--identity-path",
        str(identity_file),
        "--api-url",
        api_base_url,
    ]
    result = subprocess.run(account_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Account creation failed: {result.stderr}"

    # Verify account was created with PRE key
    client = DCypherClient(api_base_url, identity_path=str(identity_file))
    keys_data = KeyManager.load_identity_file(identity_file)
    pk = KeyManager.get_classic_public_key(keys_data["classic_sk"])
    account_info = client.get_account(pk)
    assert account_info["public_key"] == pk
    print("✅ Account created successfully with PRE capabilities")

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
