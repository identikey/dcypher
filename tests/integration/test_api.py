import ecdsa
import hashlib
import oqs
import pytest
import time
import os
import json
import requests
import collections
from unittest import mock
from main import (
    app,
)
from app_state import state
from src.lib.pq_auth import SUPPORTED_SIG_ALGS
from config import ML_DSA_ALG
from src.lib import idk_message, pre


@pytest.fixture
def storage_paths(tmp_path, monkeypatch):
    """
    NOTE: This is a temporary fixture to allow other tests to import it
    without breaking. It will be removed once all integration tests are
    refactored to use the `live_api_server` fixture, which handles
    storage isolation automatically.

    Provides isolated temporary storage paths for tests.
    """
    block_store_path = tmp_path / "block_store"
    chunk_store_path = tmp_path / "chunk_store"
    block_store_path.mkdir(exist_ok=True)
    chunk_store_path.mkdir(exist_ok=True)

    # Patch the config module attributes
    monkeypatch.setattr("config.BLOCK_STORE_ROOT", str(block_store_path))
    monkeypatch.setattr("config.CHUNK_STORE_ROOT", str(chunk_store_path))

    yield str(block_store_path), str(chunk_store_path)


@pytest.fixture(autouse=True)
def cleanup():
    """
    NOTE: This is a temporary fixture to allow other tests to import it
    without breaking. It will be removed once all integration tests are
    refactored.
    """
    # Reset in-memory state before each test
    state.accounts.clear()
    state.used_nonces.clear()
    state.graveyard.clear()
    state.block_store.clear()
    state.chunk_store.clear()

    yield

    # In-memory state is cleared again for good measure after the test
    state.accounts.clear()
    state.used_nonces.clear()
    state.graveyard.clear()
    state.block_store.clear()
    state.chunk_store.clear()


def get_nonce(api_base_url: str):
    """
    Helper function to request a nonce from the /nonce endpoint.
    Uses the API client for consistent behavior.
    """
    from src.lib.api_client import DCypherClient

    client = DCypherClient(api_base_url)
    return client.get_nonce()


def test_get_nonce_endpoint(api_base_url: str):
    """
    Tests the /nonce endpoint to ensure it returns a valid, well-formed nonce.
    """
    from src.lib.api_client import DCypherClient

    # Create API client (no auth needed for getting nonce)
    client = DCypherClient(api_base_url)

    # Get nonce using API client
    nonce = client.get_nonce()

    # The nonce should be in the format "timestamp:mac"
    parts = nonce.split(":")
    assert len(parts) == 2
    # Further validation of the nonce's cryptographic properties is implicitly
    # tested by the various `create_account` tests that consume the nonce.


def _create_test_idk_file(content: bytes) -> tuple[bytes, str]:
    """
    Creates a valid, spec-compliant IDK message for testing API endpoints.

    This helper function handles the necessary cryptographic setup:
    1. Generates a fresh crypto context (for PRE).
    2. Generates a PRE public/private key pair.
    3. Generates an ECDSA key pair for signing the IDK message headers.
    4. Encrypts the provided content and packages it into a single IDK message part.
       (For simplicity, it assumes content fits in one part).

    Args:
        content: The raw bytes to be encrypted and packaged.

    Returns:
        A tuple containing:
        - The raw bytes of the generated IDK message part.
        - The MerkleRoot of the message, to be used as the `file_hash`.
    """
    # 1. & 2. Crypto Context and PRE Keys
    cc = pre.create_crypto_context()
    keys = pre.generate_keys(cc)

    # 3. IDK Message Signing Key
    sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    # 4. Create the IDK message part
    # For testing, we assume the content fits into a single part.
    message_parts = idk_message.create_idk_message_parts(
        data=content,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk_idk_signer,
    )
    idk_file_bytes = message_parts[0].encode("utf-8")

    # 5. Extract MerkleRoot to use as the file_hash
    parsed_part = idk_message.parse_idk_message_part(message_parts[0])
    merkle_root = parsed_part["headers"]["MerkleRoot"]

    return idk_file_bytes, merkle_root


def _create_test_idk_file_parts(content: bytes) -> tuple[list[str], str]:
    """
    Creates a valid, spec-compliant IDK message, split into multiple parts.

    Similar to _create_test_idk_file but returns all string parts.
    """
    cc = pre.create_crypto_context()
    keys = pre.generate_keys(cc)
    sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    message_parts = idk_message.create_idk_message_parts(
        data=content,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk_idk_signer,
    )

    parsed_part = idk_message.parse_idk_message_part(message_parts[0])
    merkle_root = parsed_part["headers"]["MerkleRoot"]

    return message_parts, merkle_root


def create_test_account_with_keymanager(
    api_base_url: str, tmp_path, additional_pq_algs: list[str] | None = None
):
    """
    Creates a test account using KeyManager directly for maximum simplicity.
    This is the most streamlined approach for tests that just need a working account.

    Usage pattern:
        client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)
        # Account is ready to use with client

    Args:
        api_base_url: API server URL
        tmp_path: Temporary directory for auth files
        additional_pq_algs: Additional PQ algorithms beyond ML-DSA

    Returns:
        tuple: (DCypherClient, pk_classic_hex)
    """
    from src.lib.api_client import DCypherClient
    from pathlib import Path

    # Use the enhanced factory method with KeyManager
    return DCypherClient.create_test_account(
        api_base_url, Path(tmp_path), additional_pq_algs
    )


def create_test_keys_with_keymanager(
    tmp_path, additional_pq_algs: list[str] | None = None
):
    """
    Creates test keys using KeyManager without creating an account.
    Useful for tests that need keys but want to handle account creation manually.

    Args:
        tmp_path: Temporary directory for auth files
        additional_pq_algs: Additional PQ algorithms beyond ML-DSA

    Returns:
        tuple: (pk_classic_hex, auth_keys_file_path)
    """
    from src.lib.key_manager import KeyManager
    from pathlib import Path

    # Use KeyManager to create auth keys bundle
    return KeyManager.create_auth_keys_bundle(Path(tmp_path), additional_pq_algs)
