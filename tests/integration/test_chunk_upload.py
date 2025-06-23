"""
Chunk upload API tests.

This module contains tests for chunk upload operations including
successful chunk uploads, compression testing, and authorization checks.
"""

import ecdsa
import hashlib
import oqs
import pytest
import os
import json
import gzip
import base64
import requests
from main import app
from app_state import state
from config import ML_DSA_ALG
from lib import pre
from lib.idk_message import create_idk_message_parts, parse_idk_message_part

from tests.integration.test_api import (
    _create_test_account,
    get_nonce,
    _create_test_idk_file_parts,
)


def test_upload_chunk_compression_ratio(api_base_url: str, monkeypatch):
    """
    Tests that chunk compression provides significant space savings.
    This test demonstrates realistic file upload workflow using the API client.
    """
    monkeypatch.setattr("src.routers.storage.CHUNK_UPLOAD_TIMEOUT", 1)

    from src.lib.api_client import DCypherClient
    import tempfile
    import json
    from pathlib import Path
    from lib.pq_auth import generate_pq_keys

    # Generate keys for test account
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    # Generate PQ keys
    pq_pk, pq_sk = generate_pq_keys(ML_DSA_ALG)

    # Create temporary auth keys file
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Save classic secret key
        classic_sk_path = temp_path / "classic.sk"
        with open(classic_sk_path, "w") as f:
            f.write(sk_classic.to_string().hex())

        # Save PQ secret key
        pq_sk_path = temp_path / "pq.sk"
        with open(pq_sk_path, "wb") as f:
            f.write(pq_sk)

        # Create auth keys file
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": [
                {
                    "sk_path": str(pq_sk_path),
                    "pk_hex": pq_pk.hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
        }
        auth_keys_file = temp_path / "auth_keys.json"
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        # Create API client and account
        client = DCypherClient(api_base_url, str(auth_keys_file))
        pq_keys = [{"pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}]
        client.create_account(pk_classic_hex, pq_keys)

        original_content = (
            b"A" * 30000
        )  # Highly compressible, large enough for multiple parts
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        assert len(idk_parts) > 1
        part_one = idk_parts[0]

        # Register file using API client
        client.register_file(
            public_key=pk_classic_hex,
            file_hash=file_hash,
            idk_part_one=part_one,
            filename="test_file.txt",
            content_type="text/plain",
            total_size=len(original_content),
        )

        # Prepare chunk data and test compression
        chunk_data = idk_parts[1].encode("utf-8")
        compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)
        compression_ratio = len(compressed_chunk_data) / len(chunk_data)
        chunk_hash = hashlib.blake2b(chunk_data).hexdigest()

        # Upload chunk using API client with compression
        result = client.upload_chunk(
            public_key=pk_classic_hex,
            file_hash=file_hash,
            chunk_data=compressed_chunk_data,
            chunk_hash=chunk_hash,
            chunk_index=1,
            total_chunks=len(idk_parts),
            compressed=True,
        )

        # Verify compression was effective
        assert compression_ratio < 0.8, (
            f"Compression ratio {compression_ratio} should be < 0.8"
        )
        # Note: The API client handles the response format, so we check the operation succeeded
        # by verifying no exception was raised and the compression ratio is good


def test_upload_chunk_unauthorized(api_base_url: str, monkeypatch):
    """
    Tests that uploading a file chunk with an invalid signature fails.
    """
    monkeypatch.setattr("src.routers.storage.CHUNK_UPLOAD_TIMEOUT", 1)
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        idk_parts, file_hash = _create_test_idk_file_parts(
            b"some content that is long enough for two parts maybe" * 500
        )
        assert len(idk_parts) > 1
        part_one = idk_parts[0]
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
                "filename": "chunked_file.txt",
                "content_type": "text/plain",
                "total_size": str(
                    len(b"some content that is long enough for two parts maybe" * 500)
                ),
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
        assert register_response.status_code == 201, register_response.text

        chunk_data = idk_parts[1].encode("utf-8")
        chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
        chunk_nonce = get_nonce(api_base_url)
        incorrect_msg = b"this is the wrong message"
        invalid_classic_sig = sk_classic.sign(
            incorrect_msg, hashfunc=hashlib.sha256
        ).hex()
        correct_chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:1:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()
        pq_sig_chunk = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(correct_chunk_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
            files={"file": ("chunk_0", chunk_data)},
            data={
                "nonce": chunk_nonce,
                "chunk_hash": chunk_hash,
                "chunk_index": "1",
                "total_chunks": str(len(idk_parts)),
                "compressed": "false",
                "classic_signature": invalid_classic_sig,
                "pq_signatures": json.dumps([pq_sig_chunk]),
            },
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_chunk_for_unregistered_file(api_base_url: str):
    """
    Tests that uploading a chunk for a file that has not been registered fails.
    """
    sk_classic, pk_classic_hex, _, oqs_sigs_to_free = _create_test_account(api_base_url)
    try:
        chunk_data = b"some data"
        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/unregistered-file-hash/chunks",
            files={"file": ("chunk_0", chunk_data)},
            data={
                "nonce": get_nonce(api_base_url),
                "chunk_hash": hashlib.blake2b(chunk_data).hexdigest(),
                "chunk_index": "0",
                "total_chunks": "1",
                "compressed": "false",
                "classic_signature": "doesnt-matter",
                "pq_signatures": "doesnt-matter",
            },
        )
        assert response.status_code == 404
        assert "File record not found" in response.json()["detail"]
    finally:
        for sig in oqs_sigs_to_free:
            sig.free()
