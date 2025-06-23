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
import requests
from main import app
from config import ML_DSA_ALG

from tests.integration.test_api import (
    _create_test_account,
    get_nonce,
    _create_test_idk_file_parts,
)


def test_successful_upload_workflow(api_base_url: str):
    """
    Tests the successful end-to-end workflow of uploading a multi-chunk file.
    This includes registration, uploading all chunks, and verifying metadata.
    """
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Prepare file parts for a multi-chunk upload
        original_content = (
            b"This is a test file designed to span multiple chunks for upload." * 500
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]
        assert len(data_chunks) > 0, "Test content is too small for multiple chunks"

        # 3. Register the file by uploading the first part
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        classic_sig = sk_classic.sign(register_msg, hashfunc=hashlib.sha256).hex()
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(register_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "multi_chunk_test.txt",
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
        for i, chunk_content in enumerate(data_chunks, start=1):
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()

            upload_nonce = get_nonce(api_base_url)
            upload_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{total_parts}:{chunk_hash}:{upload_nonce}".encode()

            classic_sig = sk_classic.sign(upload_msg, hashfunc=hashlib.sha256).hex()
            pq_sig = {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(upload_msg).hex(),
                "alg": ML_DSA_ALG,
            }

            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={
                    "file": (
                        f"chunk_{i}",
                        chunk_bytes,
                        "application/octet-stream",
                    )
                },
                data={
                    "nonce": upload_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(total_parts),
                    "classic_signature": classic_sig,
                    "pq_signatures": json.dumps([pq_sig]),
                },
            )
            assert chunk_response.status_code == 200, chunk_response.text

        # 5. Verify file metadata and status
        meta_response = requests.get(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}"
        )
        assert meta_response.status_code == 200
        metadata = meta_response.json()
        assert metadata["filename"] == "multi_chunk_test.txt"
        assert metadata["size"] == len(original_content)
        assert metadata["status"] == "completed"

        # 6. Verify file appears in the user's file list
        list_response = requests.get(f"{api_base_url}/storage/{pk_classic_hex}")
        assert list_response.status_code == 200
        assert file_hash in list_response.json()["files"]

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_register_file_invalid_merkle_root(api_base_url: str):
    """
    Tests that file registration fails if the MerkleRoot in the IDK part
    does not match the hash derived from the content (simulated).
    The server now derives the hash, so the client cannot lie. This test
    checks if a malformed IDK part is rejected.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Create a valid IDK part, then tamper with the MerkleRoot header
        idk_parts, real_file_hash = _create_test_idk_file_parts(b"content")
        part_one = idk_parts[0]
        tampered_part_one = part_one.replace(real_file_hash, "fakehash123")

        # The signature is now invalid, but let's test the server's parsing
        # by creating a new valid signature for a fake hash.
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{real_file_hash}:{register_nonce}".encode()
        )
        classic_sig = sk_classic.sign(register_msg, hashfunc=hashlib.sha256).hex()
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(register_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
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


def test_upload_unauthorized_registration(api_base_url: str):
    """
    Tests that file registration fails if signatures are invalid.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        idk_parts, file_hash = _create_test_idk_file_parts(b"content")
        part_one = idk_parts[0]

        register_nonce = get_nonce(api_base_url)
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

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
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


def test_register_file_malformed_pq_signatures(api_base_url: str):
    """
    Tests that file registration fails if pq_signatures is not valid JSON.
    """
    _, pk_classic_hex, _, oqs_sigs_to_free = _create_test_account(api_base_url)
    try:
        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": (
                    "test.idk.part1",
                    b"some content",
                    "application/octet-stream",
                )
            },
            data={
                "nonce": get_nonce(api_base_url),
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
