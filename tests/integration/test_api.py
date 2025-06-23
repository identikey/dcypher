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
from lib.pq_auth import SUPPORTED_SIG_ALGS
from config import ML_DSA_ALG
from lib import idk_message, pre


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


def _create_test_account(
    api_base_url: str,
    add_pq_algs: list[str] | None = None,
) -> tuple[
    ecdsa.SigningKey, str, dict[str, tuple[oqs.Signature, str]], list[oqs.Signature]
]:
    """
    Helper function to create a test account.

    Args:
        add_pq_algs: A list of additional PQ algorithms to create keys for.

    Returns:
        A tuple containing:
        - The classic signing key object.
        - The classic public key hex string.
        - A dictionary of PQ signing objects and their algorithms.
        - A list of all created oqs.Signature objects for cleanup.
    """
    if add_pq_algs is None:
        add_pq_algs = []

    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    all_pq_sks: dict[str, tuple[oqs.Signature, str]] = {}
    all_pks_hex: list[str] = [pk_classic_hex]
    additional_pq_payload = []
    all_algs = [ML_DSA_ALG] + add_pq_algs

    oqs_sigs = [oqs.Signature(alg) for alg in all_algs]

    # Mandatory ML-DSA key
    sig_ml_dsa = oqs_sigs[0]
    pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
    all_pks_hex.append(pk_ml_dsa_hex)
    all_pq_sks[pk_ml_dsa_hex] = (sig_ml_dsa, ML_DSA_ALG)

    # Additional PQ keys
    for i, alg in enumerate(add_pq_algs):
        sig_add_pq = oqs_sigs[i + 1]
        pk_add_pq_hex = sig_add_pq.generate_keypair().hex()
        all_pks_hex.append(pk_add_pq_hex)
        all_pq_sks[pk_add_pq_hex] = (sig_add_pq, alg)

    # Create message and signatures
    nonce = get_nonce(api_base_url)
    message = f"{':'.join(all_pks_hex)}:{nonce}".encode("utf-8")

    sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
    sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

    for pk_hex, (sig_obj, _) in all_pq_sks.items():
        if pk_hex != pk_ml_dsa_hex:
            additional_pq_payload.append(
                {
                    "public_key": pk_hex,
                    "signature": sig_obj.sign(message).hex(),
                    "alg": all_pq_sks[pk_hex][1],
                }
            )

    # Create account using API client
    from src.lib.api_client import DCypherClient

    client = DCypherClient(api_base_url)

    # Create account payload
    payload = {
        "public_key": pk_classic_hex,
        "signature": sig_classic_hex,
        "ml_dsa_signature": {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa_hex,
            "alg": ML_DSA_ALG,
        },
        "nonce": nonce,
    }
    if additional_pq_payload:
        payload["additional_pq_signatures"] = additional_pq_payload

    # Use the API client's _handle_response method for consistent error handling
    response = requests.post(f"{api_base_url}/accounts", json=payload)
    result = client._handle_response(response)

    return sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs


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


# Define a named tuple for the setup data to provide clear types
SetupData = collections.namedtuple(
    "SetupData",
    [
        "sk_classic",
        "pk_classic_hex",
        "all_pq_sks",
        "oqs_sigs_to_free",
        "file_hash",
        "original_content",
        "full_idk_file",
        "uploaded_chunks",
        "total_chunks",
    ],
)


def setup_uploaded_file(api_base_url: str, tmp_path) -> SetupData:
    """A helper to set up a fully uploaded file with chunks for download tests."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        original_content = (
            b"This is a test file for downloading, with enough content to create multiple chunks."
            * 250
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]

        # Register the file
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "download_test.txt",
                "content_type": "text/plain",
                "total_size": str(len(original_content)),
                "classic_signature": sk_classic.sign(
                    register_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa_hex,
                            "signature": sig_ml_dsa.sign(register_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )
        assert register_response.status_code == 201

        # Upload subsequent chunks
        uploaded_chunks_info = []
        for i, chunk_content in enumerate(data_chunks, start=1):
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()
            chunk_nonce = get_nonce(api_base_url)
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()

            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={"file": (f"chunk_{i}", chunk_bytes, "application/octet-stream")},
                data={
                    "nonce": chunk_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(len(idk_parts)),
                    "compressed": "false",
                    "classic_signature": sk_classic.sign(
                        chunk_msg, hashfunc=hashlib.sha256
                    ).hex(),
                    "pq_signatures": json.dumps(
                        [
                            {
                                "public_key": pk_ml_dsa_hex,
                                "signature": sig_ml_dsa.sign(chunk_msg).hex(),
                                "alg": ML_DSA_ALG,
                            }
                        ]
                    ),
                },
            )
            assert chunk_response.status_code == 200
            uploaded_chunks_info.append(
                {"hash": chunk_hash, "original_data": chunk_bytes}
            )

        # The full IDK file content is needed for verification after download
        full_idk_file = "".join(idk_parts)

        # Note: OQS signatures will be automatically freed when exiting the context
        # For this helper function, we return empty lists for backward compatibility
        return SetupData(
            sk_classic=sk_classic,
            pk_classic_hex=pk_classic_hex,
            all_pq_sks={},  # Empty for compatibility - caller should use context manager pattern
            oqs_sigs_to_free=[],  # Empty for compatibility - automatic cleanup now
            file_hash=file_hash,
            original_content=original_content,
            full_idk_file=full_idk_file.encode("utf-8"),
            uploaded_chunks=uploaded_chunks_info,
            total_chunks=len(idk_parts),
        )


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
