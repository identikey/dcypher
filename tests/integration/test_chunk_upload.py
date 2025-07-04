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
from dcypher.app_state import state
from dcypher.config import ML_DSA_ALG
from dcypher.lib import pre
from dcypher.lib.idk_message import create_idk_message_parts, parse_idk_message_part

from tests.integration.test_api import (
    get_nonce,
    _create_test_idk_file_parts,
    create_test_account_with_keymanager,
)


def test_upload_chunk_compression_ratio(api_base_url: str, monkeypatch, tmp_path):
    """
    Tests that chunk compression provides significant space savings.
    This test demonstrates realistic file upload workflow using the API client.
    """
    monkeypatch.setattr("dcypher.routers.storage.CHUNK_UPLOAD_TIMEOUT", 1)

    # Create account using the new KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

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


def test_upload_chunk_unauthorized(api_base_url: str, tmp_path, monkeypatch):
    """
    Tests that uploading a file chunk with an invalid signature fails.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    monkeypatch.setattr("dcypher.routers.storage.CHUNK_UPLOAD_TIMEOUT", 1)

    # Create account using the new KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

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
    # OQS signatures are automatically freed when exiting the context


def test_upload_chunk_for_unregistered_file(api_base_url: str, tmp_path):
    """
    Tests that uploading a chunk for a file that has not been registered fails.
    This test demonstrates the new API client pattern for validation tests.
    """
    # Create account using the new KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

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

    # Note: No manual cleanup needed - the new API client manages resources properly
