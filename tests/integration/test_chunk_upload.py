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
from fastapi.testclient import TestClient
from main import app
from app_state import state
from config import ML_DSA_ALG
from lib import pre
from lib.idk_message import create_idk_message_parts, parse_idk_message_part

from tests.integration.test_api import (
    storage_paths,
    cleanup,
    _create_test_account,
    get_nonce,
    _create_test_idk_file_parts,
)

client = TestClient(app)


def test_upload_chunks_successful(storage_paths, monkeypatch):
    """
    Tests the successful upload of multiple file chunks after registering the
    main file metadata.
    """
    # Reduce timeout to prevent test from hanging
    monkeypatch.setattr("src.routers.storage.CHUNK_UPLOAD_TIMEOUT", 1)

    block_store_root, chunk_store_root = storage_paths
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Use larger content to ensure multiple chunks are created
        original_content = (
            b"This is a test file that will be chunked into multiple pieces." * 500
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        assert len(idk_parts) > 1, (
            "Test content was too small to create multiple chunks."
        )
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]

        register_nonce = get_nonce()
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        classic_sig_register = sk_classic.sign(
            register_msg, hashfunc=hashlib.sha256
        ).hex()
        pq_sig_register = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(register_msg).hex(),
            "alg": ML_DSA_ALG,
        }
        register_response = client.post(
            f"/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "chunked_file.txt",
                "content_type": "text/plain",
                "total_size": str(len(original_content)),
                "classic_signature": classic_sig_register,
                "pq_signatures": json.dumps([pq_sig_register]),
            },
        )
        assert register_response.status_code == 201, register_response.text

        total_chunks = len(idk_parts)
        for i, chunk_content in enumerate(data_chunks, start=1):
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()
            chunk_nonce = get_nonce()
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{total_chunks}:{chunk_hash}:{chunk_nonce}".encode()

            classic_sig_chunk = sk_classic.sign(
                chunk_msg, hashfunc=hashlib.sha256
            ).hex()
            pq_sig_chunk = {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(chunk_msg).hex(),
                "alg": ML_DSA_ALG,
            }

            response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={"file": (f"chunk_{i}", chunk_bytes)},
                data={
                    "nonce": chunk_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(total_chunks),
                    "compressed": "false",
                    "classic_signature": classic_sig_chunk,
                    "pq_signatures": json.dumps([pq_sig_chunk]),
                },
            )
            assert response.status_code == 200, response.text

        concatenated_file_path = os.path.join(
            block_store_root, f"{file_hash}.chunks.gz"
        )
        assert os.path.exists(concatenated_file_path)

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_chunk_compression_ratio(storage_paths, monkeypatch):
    """
    Tests that chunk compression provides significant space savings.
    """
    monkeypatch.setattr("src.routers.storage.CHUNK_UPLOAD_TIMEOUT", 1)
    _, chunk_store_root = storage_paths
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        original_content = (
            b"A" * 30000
        )  # Highly compressible, large enough for multiple parts
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        assert len(idk_parts) > 1
        part_one = idk_parts[0]

        register_nonce = get_nonce()
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = client.post(
            f"/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "test_file.txt",
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
        assert register_response.status_code == 201, register_response.text

        chunk_data = idk_parts[1].encode("utf-8")
        compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)
        compression_ratio = len(compressed_chunk_data) / len(chunk_data)

        chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
        chunk_nonce = get_nonce()
        chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:1:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()
        classic_sig_chunk = sk_classic.sign(chunk_msg, hashfunc=hashlib.sha256).hex()
        pq_sig_chunk = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(chunk_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks",
            files={"file": ("compressed_chunk", compressed_chunk_data)},
            data={
                "nonce": chunk_nonce,
                "chunk_hash": chunk_hash,
                "chunk_index": "1",
                "total_chunks": str(len(idk_parts)),
                "compressed": "true",
                "classic_signature": classic_sig_chunk,
                "pq_signatures": json.dumps([pq_sig_chunk]),
            },
        )
        assert response.status_code == 200, response.text
        assert "compressed" in response.json()["message"]
        assert compression_ratio < 0.8

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_chunk_unauthorized(storage_paths, monkeypatch):
    """
    Tests that uploading a file chunk with an invalid signature fails.
    """
    monkeypatch.setattr("src.routers.storage.CHUNK_UPLOAD_TIMEOUT", 1)
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        idk_parts, file_hash = _create_test_idk_file_parts(
            b"some content that is long enough for two parts maybe" * 500
        )
        assert len(idk_parts) > 1
        part_one = idk_parts[0]
        register_nonce = get_nonce()
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = client.post(
            f"/storage/{pk_classic_hex}/register",
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
        chunk_nonce = get_nonce()
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

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks",
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


def test_upload_chunk_for_unregistered_file():
    """
    Tests that uploading a chunk for a file that has not been registered fails.
    """
    sk_classic, pk_classic_hex, _, oqs_sigs_to_free = _create_test_account()
    try:
        chunk_data = b"some data"
        response = client.post(
            f"/storage/{pk_classic_hex}/unregistered-file-hash/chunks",
            files={"file": ("chunk_0", chunk_data)},
            data={
                "nonce": get_nonce(),
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
