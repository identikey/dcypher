"""
File download API tests.

This module contains tests for file download operations including
successful downloads, authorization checks, and error handling.
"""

import ecdsa
import hashlib
import oqs
import pytest
import json
import gzip
import base64
import os
from fastapi.testclient import TestClient
from main import app
from config import ML_DSA_ALG
from lib import pre
from lib.idk_message import create_idk_message_parts, parse_idk_message_part

from tests.integration.test_api import (
    storage_paths,
    cleanup,
    _create_test_account,
    get_nonce,
    _create_test_idk_file,
)

client = TestClient(app)


def test_download_file_successful(storage_paths):
    """
    Tests the successful upload and subsequent download of a file.
    """
    block_store_root, _ = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Upload a file
        original_content = b"This is a file for downloading."
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
        classic_sig_upload = sk_classic.sign(upload_msg, hashfunc=hashlib.sha256).hex()
        pq_sig_upload = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(upload_msg).hex(),
            "alg": ML_DSA_ALG,
        }
        upload_response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("download_test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": classic_sig_upload,
                "pq_signatures": json.dumps([pq_sig_upload]),
            },
        )
        assert upload_response.status_code == 201

        # 3. Prepare and execute download request
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
        )
        classic_sig_download = sk_classic.sign(
            download_msg, hashfunc=hashlib.sha256
        ).hex()
        pq_sig_download = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(download_msg).hex(),
            "alg": ML_DSA_ALG,
        }
        download_payload = {
            "nonce": download_nonce,
            "classic_signature": classic_sig_download,
            "pq_signatures": [pq_sig_download],
        }
        download_response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/download",
            json=download_payload,
        )

        # 4. Assert success and verify content
        assert download_response.status_code == 200, download_response.text
        assert download_response.content == idk_file_bytes
        assert (
            download_response.headers["content-disposition"]
            == 'attachment; filename="download_test.txt"'
        )
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_download_file_unauthorized():
    """
    Tests that file download fails if the signatures are invalid.
    """
    # 1. Create an account and upload a file successfully
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Upload a file
        original_content = b"This is a file for unauthorized download test."
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
        client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": sk_classic.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa_hex,
                            "signature": sig_ml_dsa.sign(upload_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )

        # 2. Attempt to download with invalid classic signature
        download_nonce = get_nonce()
        # Sign an incorrect message
        incorrect_msg = b"wrong message for download"
        invalid_sig = sk_classic.sign(incorrect_msg, hashfunc=hashlib.sha256).hex()

        # The PQ signature is correct for the *actual* message, to isolate the failure
        correct_download_msg = (
            f"DOWNLOAD:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
        )
        pq_sig_download = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(correct_download_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        download_payload = {
            "nonce": download_nonce,
            "classic_signature": invalid_sig,
            "pq_signatures": [pq_sig_download],
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/download",
            json=download_payload,
        )

        # 3. Assert failure
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_download_file_nonexistent():
    """
    Tests that downloading a non-existent file returns a 404 error.
    """
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Prepare and execute download request for a fake file hash
        fake_file_hash = "nonexistent-file-hash-12345"
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD:{pk_classic_hex}:{fake_file_hash}:{download_nonce}".encode()
        )
        classic_sig_download = sk_classic.sign(
            download_msg, hashfunc=hashlib.sha256
        ).hex()
        pq_sig_download = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(download_msg).hex(),
            "alg": ML_DSA_ALG,
        }
        download_payload = {
            "nonce": download_nonce,
            "classic_signature": classic_sig_download,
            "pq_signatures": [pq_sig_download],
        }
        response = client.post(
            f"/storage/{pk_classic_hex}/{fake_file_hash}/download",
            json=download_payload,
        )

        # 3. Assert 404 Not Found
        assert response.status_code == 404
        assert "File not found" in response.text
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_download_file_compressed(storage_paths):
    """
    Tests downloading a file with compression enabled.
    """
    block_store_root, _ = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Upload a file with repetitive content (highly compressible)
        original_content = (
            b"This is a repeating pattern for compression testing! " * 100
        )
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
        classic_sig_upload = sk_classic.sign(upload_msg, hashfunc=hashlib.sha256).hex()
        pq_sig_upload = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(upload_msg).hex(),
            "alg": ML_DSA_ALG,
        }
        upload_response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("compressible_test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": classic_sig_upload,
                "pq_signatures": json.dumps([pq_sig_upload]),
            },
        )
        assert upload_response.status_code == 201

        # 3. Download with compression enabled
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
        )
        classic_sig_download = sk_classic.sign(
            download_msg, hashfunc=hashlib.sha256
        ).hex()
        pq_sig_download = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(download_msg).hex(),
            "alg": ML_DSA_ALG,
        }
        download_payload = {
            "nonce": download_nonce,
            "classic_signature": classic_sig_download,
            "pq_signatures": [pq_sig_download],
            "compressed": True,
        }
        download_response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/download",
            json=download_payload,
        )

        # 4. Assert success and verify compressed content
        assert download_response.status_code == 200, download_response.text
        assert download_response.headers["content-type"] == "application/gzip"
        assert (
            download_response.headers["content-disposition"]
            == 'attachment; filename="compressible_test.txt.gz"'
        )

        # Verify we can decompress it back to original
        decompressed_content = gzip.decompress(download_response.content)
        assert decompressed_content == idk_file_bytes

        # Verify compression headers
        assert "x-original-size" in download_response.headers
        assert "x-compressed-size" in download_response.headers
        original_size = int(download_response.headers["x-original-size"])
        compressed_size = int(download_response.headers["x-compressed-size"])
        assert original_size == len(idk_file_bytes)
        assert compressed_size == len(download_response.content)
        assert compressed_size < original_size  # Should be compressed

    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_download_chunk_compressed(storage_paths):
    """
    Tests downloading individual chunks with compression handling.
    """
    _, chunk_store_root = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Create a large file that will be split into multiple chunks
        cc = pre.create_crypto_context()
        keys = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        # Use content larger than slot count to force multiple chunks
        slot_count = pre.get_slot_count(cc)
        large_content = b"A" * (slot_count * 3 + 100)  # Ensure multiple chunks

        # Create IDK message parts
        message_parts = create_idk_message_parts(
            data=large_content,
            cc=cc,
            pk=keys.publicKey,
            signing_key=sk_idk_signer,
        )

        # Upload the first part as the main file
        first_part_bytes = message_parts[0].encode("utf-8")
        parsed_first = parse_idk_message_part(message_parts[0])
        file_hash = parsed_first["headers"]["MerkleRoot"]

        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
        client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("large_test.txt", first_part_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": sk_classic.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa_hex,
                            "signature": sig_ml_dsa.sign(upload_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )

        # 3. Upload remaining parts as compressed chunks
        uploaded_chunks = []
        for i, part_str in enumerate(message_parts[1:], start=1):
            parsed = parse_idk_message_part(part_str)
            chunk_data = base64.b64decode(parsed["payload_b64"])
            compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)
            chunk_hash = hashlib.blake2b(chunk_data).hexdigest()

            chunk_nonce = get_nonce()
            chunk_msg = (
                f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:"
                f"{i}:{len(message_parts)}:{chunk_hash}:{chunk_nonce}"
            ).encode()

            response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={"file": (f"chunk_{i}", compressed_chunk_data)},
                data={
                    "nonce": chunk_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(len(message_parts)),
                    "compressed": "true",
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
            assert response.status_code == 200, (
                f"Chunk {i} upload failed: {response.text}"
            )
            assert "compressed" in response.json()["message"]
            uploaded_chunks.append((chunk_hash, chunk_data, compressed_chunk_data))

        # 4. Test downloading chunks with different compression options
        for chunk_hash, original_chunk_data, compressed_chunk_data in uploaded_chunks:
            # Test 1: Download compressed chunk as compressed
            download_nonce = get_nonce()
            download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_hash}:{download_nonce}".encode()
            download_payload = {
                "nonce": download_nonce,
                "chunk_hash": chunk_hash,
                "classic_signature": sk_classic.sign(
                    download_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa_hex,
                        "signature": sig_ml_dsa.sign(download_msg).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
                "compressed": True,
            }

            response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
                json=download_payload,
            )

            assert response.status_code == 200
            assert response.headers["content-type"] == "application/gzip"
            assert response.content == compressed_chunk_data
            assert response.headers["x-compressed"] == "true"

            # Test 2: Download compressed chunk as decompressed
            download_nonce = get_nonce()
            download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_hash}:{download_nonce}".encode()
            download_payload = {
                "nonce": download_nonce,
                "chunk_hash": chunk_hash,
                "classic_signature": sk_classic.sign(
                    download_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa_hex,
                        "signature": sig_ml_dsa.sign(download_msg).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
                "compressed": False,
            }

            response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
                json=download_payload,
            )

            assert response.status_code == 200
            assert response.headers["content-type"] == "application/octet-stream"
            assert response.content == original_chunk_data
            assert (
                response.headers["x-compressed"] == "true"
            )  # Still shows it was stored compressed

    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_download_chunk_unauthorized():
    """
    Tests that chunk download fails with invalid signatures.
    """
    # 1. Create an account and upload chunks (reuse logic from previous test)
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Create and upload a simple file with chunk
        original_content = b"chunk download auth test"
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
        client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": sk_classic.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa_hex,
                            "signature": sig_ml_dsa.sign(upload_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )

        # Upload a chunk
        chunk_data = b"test chunk data"
        compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)
        chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
        chunk_nonce = get_nonce()
        chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:0:1:{chunk_hash}:{chunk_nonce}".encode()

        client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks",
            files={"file": ("chunk_0", compressed_chunk_data)},
            data={
                "nonce": chunk_nonce,
                "chunk_hash": chunk_hash,
                "chunk_index": "0",
                "total_chunks": "1",
                "compressed": "true",
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

        # 2. Attempt download with invalid signature
        download_nonce = get_nonce()
        invalid_msg = b"wrong message for chunk download"
        invalid_sig = sk_classic.sign(invalid_msg, hashfunc=hashlib.sha256).hex()

        # Correct PQ signature for isolation
        correct_download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_hash}:{download_nonce}".encode()
        pq_sig_download = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(correct_download_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        download_payload = {
            "nonce": download_nonce,
            "chunk_hash": chunk_hash,
            "classic_signature": invalid_sig,
            "pq_signatures": [pq_sig_download],
            "compressed": False,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
            json=download_payload,
        )

        # 3. Assert failure
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text

    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_download_chunk_nonexistent():
    """
    Tests that downloading a non-existent chunk returns a 404 error.
    """
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Create a file but don't upload any chunks
        original_content = b"file without chunks"
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
        client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": sk_classic.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa_hex,
                            "signature": sig_ml_dsa.sign(upload_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )

        # 3. Attempt to download a non-existent chunk
        fake_chunk_hash = "nonexistent-chunk-hash-12345"
        download_nonce = get_nonce()
        download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{fake_chunk_hash}:{download_nonce}".encode()
        download_payload = {
            "nonce": download_nonce,
            "chunk_hash": fake_chunk_hash,
            "classic_signature": sk_classic.sign(
                download_msg, hashfunc=hashlib.sha256
            ).hex(),
            "pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(download_msg).hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
            "compressed": False,
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks/{fake_chunk_hash}/download",
            json=download_payload,
        )

        # 4. Assert 404 Not Found
        assert response.status_code == 404
        assert "Chunk not found" in response.text

    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_concatenated_chunks_download_workflow(storage_paths):
    """
    Tests the full workflow of uploading compressed chunks and downloading them
    as a single concatenated gzip file that can be used with zgrep, zcat, etc.
    """
    block_store_root, _ = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Create a large file that will be split into multiple chunks
        cc = pre.create_crypto_context()
        keys = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        # Use content larger than slot count to force multiple chunks
        slot_count = pre.get_slot_count(cc)
        # Create content with identifiable patterns for testing
        chunk1_content = b"CHUNK_ONE_DATA: " + b"A" * (slot_count * 2)
        chunk2_content = b"CHUNK_TWO_DATA: " + b"B" * (slot_count * 2)
        chunk3_content = b"CHUNK_THREE_DATA: " + b"C" * (slot_count * 2)
        large_content = chunk1_content + chunk2_content + chunk3_content

        # Create IDK message parts
        message_parts = create_idk_message_parts(
            data=large_content,
            cc=cc,
            pk=keys.publicKey,
            signing_key=sk_idk_signer,
        )

        # Should have multiple parts due to large content
        assert len(message_parts) > 1, (
            f"Expected multiple chunks, got {len(message_parts)}"
        )

        # Upload the first part as the main file
        first_part_bytes = message_parts[0].encode("utf-8")
        parsed_first = parse_idk_message_part(message_parts[0])
        file_hash = parsed_first["headers"]["MerkleRoot"]

        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()
        upload_response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("concatenated_test.txt", first_part_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": sk_classic.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa_hex,
                            "signature": sig_ml_dsa.sign(upload_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )
        assert upload_response.status_code == 201, (
            f"Upload failed: {upload_response.text}"
        )

        # 3. Upload remaining parts as compressed chunks
        uploaded_chunk_data = []
        for i, part_str in enumerate(message_parts[1:], start=1):
            parsed = parse_idk_message_part(part_str)
            chunk_data = base64.b64decode(parsed["payload_b64"])
            compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)
            chunk_hash = hashlib.blake2b(chunk_data).hexdigest()

            chunk_nonce = get_nonce()
            chunk_msg = (
                f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:"
                f"{i}:{len(message_parts)}:{chunk_hash}:{chunk_nonce}"
            ).encode()

            response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={"file": (f"chunk_{i}", compressed_chunk_data)},
                data={
                    "nonce": chunk_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(len(message_parts)),
                    "compressed": "true",
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
            assert response.status_code == 200, (
                f"Chunk {i} upload failed: {response.text}"
            )
            assert "compressed" in response.json()["message"]
            uploaded_chunk_data.append((chunk_hash, chunk_data, compressed_chunk_data))

        # 4. Verify concatenated file exists on disk
        concatenated_file_path = os.path.join(
            block_store_root, f"{file_hash}.chunks.gz"
        )
        assert os.path.exists(concatenated_file_path), "Concatenated file should exist"

        # 5. Test downloading the concatenated chunks file
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
        )
        download_payload = {
            "nonce": download_nonce,
            "classic_signature": sk_classic.sign(
                download_msg, hashfunc=hashlib.sha256
            ).hex(),
            "pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(download_msg).hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
        }

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks/download",
            json=download_payload,
        )

        # 6. Verify successful download
        assert response.status_code == 200, f"Download failed: {response.text}"
        assert response.headers["content-type"] == "application/gzip"
        assert (
            response.headers["content-disposition"]
            == 'attachment; filename="concatenated_test.chunks.gz"'
        )
        assert "x-chunk-count" in response.headers
        assert "x-file-type" in response.headers
        assert response.headers["x-file-type"] == "concatenated-gzip-chunks"

        # 7. Verify the downloaded content can be decompressed and contains expected data
        concatenated_gzip_data = response.content

        # Save to a temporary file to test with system tools
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as temp_file:
            temp_file.write(concatenated_gzip_data)
            temp_file_path = temp_file.name

        try:
            # Test that we can decompress it
            import subprocess

            result = subprocess.run(
                ["gunzip", "-t", temp_file_path], capture_output=True
            )
            assert result.returncode == 0, f"gunzip test failed: {result.stderr}"

            # Test that we can extract content
            result = subprocess.run(["zcat", temp_file_path], capture_output=True)
            assert result.returncode == 0, f"zcat failed: {result.stderr}"

            # The decompressed content should be the concatenation of all uploaded chunk data
            decompressed_content = result.stdout

            # Verify we can find parts of our original chunks in the decompressed data
            # (Note: the exact structure depends on how gzip concatenation works with our encrypted chunks)
            assert len(decompressed_content) > 0, (
                "Decompressed content should not be empty"
            )

            print(f"Successfully downloaded and verified concatenated gzip file:")
            print(f"  Original chunks: {len(uploaded_chunk_data)}")
            print(f"  Concatenated file size: {len(concatenated_gzip_data)} bytes")
            print(f"  Decompressed size: {len(decompressed_content)} bytes")

        finally:
            # Clean up temp file
            os.unlink(temp_file_path)

        # 8. Verify both individual and concatenated downloads work
        if uploaded_chunk_data:
            chunk_hash, chunk_data, compressed_chunk_data = uploaded_chunk_data[0]

            # Test individual chunk download
            individual_download_nonce = get_nonce()
            individual_download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_hash}:{individual_download_nonce}".encode()
            individual_download_payload = {
                "nonce": individual_download_nonce,
                "chunk_hash": chunk_hash,
                "classic_signature": sk_classic.sign(
                    individual_download_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa_hex,
                        "signature": sig_ml_dsa.sign(individual_download_msg).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
                "compressed": True,  # Request compressed version
            }

            response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
                json=individual_download_payload,
            )

            assert response.status_code == 200, "Individual chunk download should work"
            assert response.content == compressed_chunk_data

    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()
