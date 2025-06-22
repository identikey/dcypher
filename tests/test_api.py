import ecdsa
import hashlib
import oqs
import pytest
import time
import os
import json
from unittest import mock
from fastapi.testclient import TestClient
from src.main import (
    app,
    state,
    SUPPORTED_SIG_ALGS,
    ML_DSA_ALG,
)
from lib import idk_message, pre

client = TestClient(app)


@pytest.fixture
def storage_paths(tmp_path):
    """Provides isolated temporary storage paths for tests."""
    block_store_path = tmp_path / "block_store"
    chunk_store_path = tmp_path / "chunk_store"
    block_store_path.mkdir()
    chunk_store_path.mkdir()
    return str(block_store_path), str(chunk_store_path)


@pytest.fixture(autouse=True)
def cleanup(storage_paths):
    """
    Pytest fixture to reset application state and use temporary directories for storage.
    This ensures tests are isolated, especially when running in parallel with pytest-xdist.
    """
    block_store_path, chunk_store_path = storage_paths

    # Mock the storage path constants in the main application
    with (
        mock.patch("src.main.BLOCK_STORE_ROOT", block_store_path),
        mock.patch("src.main.CHUNK_STORE_ROOT", chunk_store_path),
    ):
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
    nonce = get_nonce()
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

    response = client.post("/accounts", json=payload)
    assert response.status_code == 200, response.text

    return sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs


def get_nonce():
    """
    Helper function to request a nonce from the /nonce endpoint.
    Asserts that the request is successful and returns the nonce.
    """
    response = client.get("/nonce")
    assert response.status_code == 200
    return response.json()["nonce"]


def test_get_nonce_endpoint():
    """
    Tests the /nonce endpoint to ensure it returns a valid, well-formed nonce.
    """
    response = client.get("/nonce")
    assert response.status_code == 200
    data = response.json()
    assert "nonce" in data
    nonce = data["nonce"]
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
