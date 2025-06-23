"""
File upload API tests.

This module contains tests for the chunked file upload operations including
successful uploads, validation failures, and authorization checks.
"""

import ecdsa
import hashlib
import oqs
import pytest
import json
from fastapi.testclient import TestClient
from main import app
from config import ML_DSA_ALG

from tests.integration.test_api import (
    storage_paths,
    cleanup,
    _create_test_account,
    get_nonce,
    _create_test_idk_file_parts,
)

client = TestClient(app)


def test_upload_file_successful(storage_paths):
    """
    Tests the successful chunked upload of a file.
    """
    block_store_root, _ = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Prepare file parts for chunked upload
        original_content = (
            b"This is a test file for the block store, now with more content to ensure it spans multiple chunks."
            * 20
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]

        # 3. Register the file by uploading the first part
        register_nonce = get_nonce()
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        classic_sig = sk_classic.sign(register_msg, hashfunc=hashlib.sha256).hex()
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(register_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "test.txt",
                "content_type": "text/plain",
                "total_size": str(len(original_content)),
                "classic_signature": classic_sig,
                "pq_signatures": json.dumps([pq_sig]),
            },
        )
        assert response.status_code == 201, response.text
        assert response.json()["file_hash"] == file_hash

        # 4. Upload the rest of the chunks
        total_parts = len(idk_parts)
        for i, chunk_content in enumerate(data_chunks):
            chunk_index = i + 1  # part one is index 0
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()

            upload_nonce = get_nonce()
            upload_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_index}:{total_parts}:{chunk_hash}:{upload_nonce}".encode()

            classic_sig = sk_classic.sign(upload_msg, hashfunc=hashlib.sha256).hex()
            pq_sig = {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(upload_msg).hex(),
                "alg": ML_DSA_ALG,
            }

            chunk_response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={
                    "file": (
                        f"chunk_{chunk_index}",
                        chunk_bytes,
                        "application/octet-stream",
                    )
                },
                data={
                    "nonce": upload_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(chunk_index),
                    "total_chunks": str(total_parts),
                    "classic_signature": classic_sig,
                    "pq_signatures": json.dumps([pq_sig]),
                },
            )
            assert chunk_response.status_code == 200, chunk_response.text

        # 5. Verify file metadata and content
        response = client.get(f"/storage/{pk_classic_hex}")
        assert response.status_code == 200
        assert response.json()["files"] == [file_hash]

        response = client.get(f"/storage/{pk_classic_hex}/{file_hash}")
        assert response.status_code == 200
        metadata = response.json()
        assert metadata["filename"] == "test.txt"
        assert metadata["size"] == len(original_content)
        assert metadata["status"] == "completed"

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_register_file_invalid_merkle_root():
    """
    Tests that file registration fails if the MerkleRoot in the IDK part
    does not match the hash derived from the content (simulated).
    The server now derives the hash, so the client cannot lie. This test
    checks if a malformed IDK part is rejected.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Create a valid IDK part, then tamper with the MerkleRoot header
        idk_parts, real_file_hash = _create_test_idk_file_parts(b"content")
        part_one = idk_parts[0]
        tampered_part_one = part_one.replace(real_file_hash, "fakehash123")

        # The signature is now invalid, but let's test the server's parsing
        # by creating a new valid signature for a fake hash.
        register_nonce = get_nonce()
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{real_file_hash}:{register_nonce}".encode()
        )
        classic_sig = sk_classic.sign(register_msg, hashfunc=hashlib.sha256).hex()
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(register_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": (
                    "test.idk.part1",
                    tampered_part_one,
                    "application/octet-stream",
                )
            },
            data={
                "nonce": register_nonce,
                "filename": "test.txt",
                "content_type": "text/plain",
                "total_size": "7",
                "classic_signature": classic_sig,
                "pq_signatures": json.dumps([pq_sig]),
            },
        )
        # The server will fail to verify the signature because the MerkleRoot it parses
        # from the body ("fakehash123") won't match the one used for the signature.
        assert response.status_code == 401, response.text
        assert "Invalid classic signature" in response.text

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_unauthorized_registration():
    """
    Tests that file registration fails if signatures are invalid.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        idk_parts, file_hash = _create_test_idk_file_parts(b"content")
        part_one = idk_parts[0]

        register_nonce = get_nonce()
        # Sign the wrong message
        invalid_msg = b"this is not the message to sign"
        classic_sig = sk_classic.sign(invalid_msg, hashfunc=hashlib.sha256).hex()

        # Use a valid PQ sig for this test
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(register_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "test.txt",
                "content_type": "text/plain",
                "total_size": "7",
                "classic_signature": classic_sig,
                "pq_signatures": json.dumps([pq_sig]),
            },
        )
        assert response.status_code == 401, response.text
        assert "Invalid classic signature" in response.text
    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_register_file_malformed_pq_signatures():
    """
    Tests that file registration fails if pq_signatures is not valid JSON.
    """
    _, pk_classic_hex, _, oqs_sigs_to_free = _create_test_account()
    try:
        response = client.post(
            f"/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": (
                    "test.idk.part1",
                    b"some content",
                    "application/octet-stream",
                )
            },
            data={
                "nonce": get_nonce(),
                "filename": "test.txt",
                "content_type": "text/plain",
                "total_size": "12",
                "classic_signature": "does-not-matter",
                "pq_signatures": "this-is-not-json",
            },
        )
        assert response.status_code == 400
        assert "Invalid format for pq_signatures" in response.json()["detail"]
    finally:
        for sig in oqs_sigs_to_free:
            sig.free()
