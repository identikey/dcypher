"""
File upload API tests.

This module contains tests for basic file upload operations including
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
    _create_test_idk_file,
)

client = TestClient(app)


def test_upload_file_successful(storage_paths):
    """
    Tests the successful upload of a file to an account's block store.
    """
    block_store_root, _ = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Prepare file and upload request data
        original_content = b"This is a test file for the block store."
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()

        # 3. Sign the upload message
        classic_sig = sk_classic.sign(upload_msg, hashfunc=hashlib.sha256).hex()
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(upload_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        # 4. Perform the upload
        response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": classic_sig,
                "pq_signatures": json.dumps([pq_sig]),
            },
        )

        # 5. Assert success
        assert response.status_code == 201, response.text
        assert response.json()["message"] == "File uploaded successfully"
        assert response.json()["file_hash"] == file_hash

        # 6. Verify file exists on server
        import os

        file_path = os.path.join(block_store_root, file_hash)
        assert os.path.exists(file_path)
        with open(file_path, "rb") as f:
            assert f.read() == idk_file_bytes

        # 7. Verify metadata endpoints
        response = client.get(f"/storage/{pk_classic_hex}")
        assert response.status_code == 200
        assert response.json()["files"] == [file_hash]

        response = client.get(f"/storage/{pk_classic_hex}/{file_hash}")
        assert response.status_code == 200
        metadata = response.json()
        assert metadata["filename"] == "test.txt"
        assert metadata["size"] == len(idk_file_bytes)
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_file_invalid_hash():
    """
    Tests that file upload fails if the provided hash does not match the file.
    """
    # 1. Create a real account first
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Attempt upload with incorrect hash
        original_content = b"content"
        idk_file_bytes, _ = _create_test_idk_file(original_content)
        incorrect_hash = "thisisnotthehash"
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{incorrect_hash}:{upload_nonce}".encode()

        classic_sig = sk_classic.sign(upload_msg, hashfunc=hashlib.sha256).hex()
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(upload_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": incorrect_hash,
                "classic_signature": classic_sig,
                "pq_signatures": json.dumps([pq_sig]),
            },
        )
        assert response.status_code == 400
        assert "File hash does not match MerkleRoot" in response.text
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_file_unauthorized(storage_paths):
    """
    Tests that file upload fails if signatures are invalid.
    """
    # 1. Create a real account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Attempt upload with invalid classic signature
        original_content = b"content"
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        upload_nonce = get_nonce()

        # Sign an incorrect message
        incorrect_msg = b"wrong message"
        invalid_sig = sk_classic.sign(incorrect_msg, hashfunc=hashlib.sha256).hex()
        pq_sig = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(
                f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
            ).hex(),
            "alg": ML_DSA_ALG,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": invalid_sig,
                "pq_signatures": json.dumps([pq_sig]),
            },
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_file_malformed_pq_signatures():
    """
    Tests that file upload fails if the pq_signatures field is not a valid
    JSON string.
    """
    # 1. Create a real account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        # 2. Attempt to upload with a malformed pq_signatures string
        response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test.txt", b"content", "text/plain")},
            data={
                "nonce": get_nonce(),
                "file_hash": hashlib.sha256(b"content").hexdigest(),
                "classic_signature": "doesnt-matter",
                "pq_signatures": "this-is-not-a-valid-json-string",
            },
        )
        assert response.status_code == 400
        assert "Invalid format for pq_signatures" in response.json()["detail"]
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()
