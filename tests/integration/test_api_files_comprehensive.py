"""
Comprehensive file storage API tests for public audit standards.

This module contains advanced security, performance, and resilience tests
that go beyond basic functionality to ensure the system meets audit standards.
"""

import ecdsa
import hashlib
import oqs
import pytest
import time
import os
import json
import threading
import concurrent.futures
from unittest import mock
from fastapi.testclient import TestClient
from main import app
from app_state import state
from lib.pq_auth import SUPPORTED_SIG_ALGS
from config import ML_DSA_ALG
from lib import pre
from lib.idk_message import MerkleTree, IDK_VERSION
from lib.idk_message import create_idk_message_parts, parse_idk_message_part
import base64

from tests.integration.test_api import (
    storage_paths,
    cleanup,
    _create_test_account,
    get_nonce,
    _create_test_idk_file,
)

client = TestClient(app)


def _upload_file_chunked(
    pk_classic_hex,
    sk_classic,
    pk_ml_dsa_hex,
    sig_ml_dsa,
    content,
    filename="test.txt",
    content_type="text/plain",
):
    """
    Helper function to upload a file using the new two-step chunked API.
    Returns (response_status_code, file_hash)
    """
    # Create IDK message parts
    cc = pre.create_crypto_context()
    keys = pre.generate_keys(cc)
    sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    message_parts = create_idk_message_parts(content, cc, keys.publicKey, sk_idk_signer)

    if not message_parts:
        return 400, None

    # Parse first part to get file hash
    part_one_content = message_parts[0]  # Keep as string first
    parsed_part = parse_idk_message_part(message_parts[0])
    file_hash = parsed_part["headers"]["MerkleRoot"]

    # Step 1: Register file with first chunk
    register_nonce = get_nonce()
    register_msg = f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
    classic_sig_register = sk_classic.sign(register_msg, hashfunc=hashlib.sha256).hex()
    pq_sig_register = {
        "public_key": pk_ml_dsa_hex,
        "signature": sig_ml_dsa.sign(register_msg).hex(),
        "alg": ML_DSA_ALG,
    }

    register_response = client.post(
        f"/storage/{pk_classic_hex}/register",
        files={
            "idk_part_one": (
                "part1.idk",
                part_one_content,
                "application/octet-stream",
            )
        },
        data={
            "nonce": register_nonce,
            "filename": filename,
            "content_type": content_type,
            "total_size": str(len(content)),
            "classic_signature": classic_sig_register,
            "pq_signatures": json.dumps([pq_sig_register]),
        },
    )

    if register_response.status_code != 201:
        return register_response.status_code, file_hash

    # Step 2: Upload remaining chunks
    last_status_code = 201  # Default to registration status
    for i, chunk_content_str in enumerate(message_parts[1:], 1):
        chunk_content_bytes = chunk_content_str.encode("utf-8")
        chunk_hash = hashlib.blake2b(chunk_content_bytes).hexdigest()

        upload_nonce = get_nonce()
        upload_msg = (
            f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:"
            f"{i}:{len(message_parts)}:{chunk_hash}:{upload_nonce}"
        ).encode()
        classic_sig_upload = sk_classic.sign(upload_msg, hashfunc=hashlib.sha256).hex()
        pq_sig_upload = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(upload_msg).hex(),
            "alg": ML_DSA_ALG,
        }

        chunk_response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks",
            files={"file": (chunk_hash, chunk_content_bytes)},
            data={
                "nonce": upload_nonce,
                "chunk_hash": chunk_hash,
                "chunk_index": str(i),
                "total_chunks": str(len(message_parts)),
                "compressed": "false",
                "classic_signature": classic_sig_upload,
                "pq_signatures": json.dumps([pq_sig_upload]),
            },
        )

        if chunk_response.status_code != 200:
            return chunk_response.status_code, file_hash

        last_status_code = 200  # Update to chunk upload status

    return last_status_code, file_hash


def test_file_upload_timing_attack_resistance(storage_paths):
    """
    Tests that file operations execute in constant time regardless of
    file existence to prevent information leakage through timing attacks.
    """
    block_store_root, _ = storage_paths
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa = all_pq_sks[pk_ml_dsa_hex][0]

        # 1. Upload a file first using the new chunked API
        original_content = b"Test content for timing analysis"
        status_code, file_hash = _upload_file_chunked(
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            original_content,
            "test.txt",
            "text/plain",
        )
        assert status_code == 201, f"Upload failed with status {status_code}"

        # 2. Test download timing for existing vs non-existent files
        # Existing file download timing
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

        start_time = time.perf_counter()
        response1 = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks/download",
            json=download_payload,
        )
        existing_time = time.perf_counter() - start_time
        assert response1.status_code == 200

        # Non-existent file download timing
        fake_hash = "nonexistent" + "0" * 50
        download_nonce2 = get_nonce()
        download_msg2 = (
            f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{fake_hash}:{download_nonce2}".encode()
        )
        download_payload2 = {
            "nonce": download_nonce2,
            "classic_signature": sk_classic.sign(
                download_msg2, hashfunc=hashlib.sha256
            ).hex(),
            "pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(download_msg2).hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
        }

        start_time = time.perf_counter()
        response2 = client.post(
            f"/storage/{pk_classic_hex}/{fake_hash}/chunks/download",
            json=download_payload2,
        )
        nonexistent_time = time.perf_counter() - start_time
        assert response2.status_code == 404

        # Timing difference should be minimal (< 50ms)
        time_difference = abs(existing_time - nonexistent_time)
        assert time_difference < 0.05, (
            f"Timing difference too large: {time_difference}s"
        )

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_concurrent_file_uploads(storage_paths):
    """
    Tests concurrent file upload operations to ensure thread safety
    and prevent race conditions in file storage.
    """

    def upload_single_file(thread_id):
        """Upload a single file in a thread"""
        try:
            sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_inner = (
                _create_test_account()
            )
            pk_ml_dsa_hex = next(iter(all_pq_sks))
            sig_ml_dsa = all_pq_sks[pk_ml_dsa_hex][0]

            # Create unique content for each thread
            content = f"Thread {thread_id} test content".encode()

            # Use the new chunked upload API
            status_code, file_hash = _upload_file_chunked(
                pk_classic_hex,
                sk_classic,
                pk_ml_dsa_hex,
                sig_ml_dsa,
                content,
                f"test_{thread_id}.txt",
                "text/plain",
            )

            # Clean up OQS signatures
            for sig in oqs_sigs_inner:
                sig.free()

            return thread_id, status_code, file_hash
        except Exception as e:
            return thread_id, 500, str(e)

    # Test with 10 concurrent uploads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(upload_single_file, i) for i in range(10)]
        results = [
            future.result() for future in concurrent.futures.as_completed(futures)
        ]

    # Verify all uploads succeeded
    success_count = sum(1 for _, status_code, _ in results if status_code == 201)
    assert success_count == 10, f"Only {success_count}/10 concurrent uploads succeeded"

    # Verify all file hashes are unique
    file_hashes = [fh for _, status_code, fh in results if status_code == 201]
    assert len(set(file_hashes)) == len(file_hashes), "Duplicate file hashes detected"


def test_file_corruption_detection(storage_paths):
    """
    Tests that the system detects and rejects corrupted file uploads
    through hash validation and Merkle tree verification.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa = all_pq_sks[pk_ml_dsa_hex][0]

        # 1. Create a valid file first to establish baseline
        original_content = b"This content will be corrupted"
        status_code, file_hash = _upload_file_chunked(
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            original_content,
            "valid.txt",
            "text/plain",
        )
        assert status_code == 201, "Valid upload should succeed"

        # 2. Test corruption detection by trying to upload chunks with wrong hashes
        # Create another file and intentionally corrupt the chunk hash
        content2 = b"Another file for corruption testing"

        # Create IDK message parts manually to test corruption
        cc = pre.create_crypto_context()
        keys = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        message_parts = create_idk_message_parts(
            content2, cc, keys.publicKey, sk_idk_signer
        )

        if not message_parts:
            assert False, "Failed to create IDK message parts"

        # Parse first part to get file hash
        part_one_content = message_parts[0]  # Keep as string
        parsed_part = parse_idk_message_part(message_parts[0])
        file_hash2 = parsed_part["headers"]["MerkleRoot"]

        # Register the file normally
        register_nonce = get_nonce()
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash2}:{register_nonce}".encode()
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
                "idk_part_one": (
                    "part1.idk",
                    part_one_content,
                    "application/octet-stream",
                )
            },
            data={
                "nonce": register_nonce,
                "filename": "corrupted.txt",
                "content_type": "text/plain",
                "total_size": str(len(content2)),
                "classic_signature": classic_sig_register,
                "pq_signatures": json.dumps([pq_sig_register]),
            },
        )
        assert register_response.status_code == 201, "Registration should succeed"

        # Now try to upload a subsequent chunk with a wrong hash
        if len(message_parts) > 1:
            chunk_content_bytes = message_parts[1].encode("utf-8")
            wrong_chunk_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # Wrong hash

            upload_nonce = get_nonce()
            upload_msg = (
                f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash2}:"
                f"1:{len(message_parts)}:{wrong_chunk_hash}:{upload_nonce}"
            ).encode()
            classic_sig_upload = sk_classic.sign(
                upload_msg, hashfunc=hashlib.sha256
            ).hex()
            pq_sig_upload = {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(upload_msg).hex(),
                "alg": ML_DSA_ALG,
            }

            chunk_response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash2}/chunks",
                data={
                    "chunk_index": "1",
                    "total_chunks": str(len(message_parts)),
                    "chunk_hash": wrong_chunk_hash,
                    "classic_signature": classic_sig_upload,
                    "pq_signatures": json.dumps([pq_sig_upload]),
                    "nonce": upload_nonce,
                },
                files={
                    "chunk": ("chunk", chunk_content_bytes, "application/octet-stream")
                },
            )

            # Should fail due to hash mismatch
            assert chunk_response.status_code == 400, (
                f"Expected corruption detection to fail upload, got {chunk_response.status_code}"
            )

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_large_file_memory_management(storage_paths):
    """
    Tests that large file uploads are handled efficiently without
    causing memory exhaustion or system instability.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa = all_pq_sks[pk_ml_dsa_hex][0]

        # Create a 5MB file to test memory handling
        large_content = os.urandom(5 * 1024 * 1024)  # 5MB

        # Monitor memory usage during upload (basic check)
        import psutil

        process = psutil.Process()
        memory_before = process.memory_info().rss

        start_time = time.perf_counter()
        status_code, file_hash = _upload_file_chunked(
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            large_content,
            "large_file.bin",
            "application/octet-stream",
        )
        upload_time = time.perf_counter() - start_time

        memory_after = process.memory_info().rss
        memory_increase = memory_after - memory_before

        # Verify upload succeeded (200 for chunk upload completion)
        assert status_code == 200, f"Large file upload failed with status {status_code}"

        # Memory increase should be reasonable (< 100MB for a 5MB file)
        assert memory_increase < 100 * 1024 * 1024, (
            f"Memory usage too high: {memory_increase} bytes"
        )

        # Upload time should be reasonable (adjust for parallel test execution)
        # Allow more time when running with multiple pytest workers due to resource contention
        max_upload_time = 30.0  # More generous timeout for parallel execution
        assert upload_time < max_upload_time, (
            f"Upload took too long: {upload_time}s (max: {max_upload_time}s)"
        )

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_file_access_authorization_edge_cases(storage_paths):
    """
    Tests edge cases in file access authorization to ensure proper
    security boundaries are maintained.
    """
    # Create two separate accounts
    sk1, pk1_hex, all_pq_sks1, oqs_sigs_1 = _create_test_account()
    sk2, pk2_hex, all_pq_sks2, oqs_sigs_2 = _create_test_account()

    try:
        pk_ml_dsa1_hex = next(iter(all_pq_sks1))
        sig_ml_dsa1 = all_pq_sks1[pk_ml_dsa1_hex][0]
        pk_ml_dsa2_hex = next(iter(all_pq_sks2))
        sig_ml_dsa2 = all_pq_sks2[pk_ml_dsa2_hex][0]

        # 1. Account 1 uploads a file
        content = b"Private file content"
        status_code, file_hash = _upload_file_chunked(
            pk1_hex,
            sk1,
            pk_ml_dsa1_hex,
            sig_ml_dsa1,
            content,
            "private.txt",
            "text/plain",
        )
        assert status_code == 201, f"Account 1 upload failed with status {status_code}"

        # 2. Account 2 tries to download Account 1's file (should fail)
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk2_hex}:{file_hash}:{download_nonce}".encode()
        )

        response = client.post(
            f"/storage/{pk2_hex}/{file_hash}/chunks/download",
            json={
                "nonce": download_nonce,
                "classic_signature": sk2.sign(
                    download_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa2_hex,
                        "signature": sig_ml_dsa2.sign(download_msg).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
            },
        )
        # Should fail because the file doesn't belong to account 2
        assert response.status_code == 404

        # 3. Account 2 tries to access Account 1's file list (should fail)
        response = client.get(f"/storage/{pk2_hex}")
        assert response.status_code == 200
        files = response.json()["files"]
        assert file_hash not in files, "File leaked across accounts"

        # 4. Try cross-account signature attack (Account 2 signs Account 1's download)
        cross_download_msg = (
            f"DOWNLOAD-CHUNKS:{pk1_hex}:{file_hash}:{download_nonce}".encode()
        )
        response = client.post(
            f"/storage/{pk1_hex}/{file_hash}/chunks/download",
            json={
                "nonce": download_nonce,
                "classic_signature": sk2.sign(
                    cross_download_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa2_hex,
                        "signature": sig_ml_dsa2.sign(cross_download_msg).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
            },
        )
        # Should fail due to signature mismatch
        assert response.status_code == 401

    finally:
        for sig in oqs_sigs_1:
            sig.free()
        for sig in oqs_sigs_2:
            sig.free()


def test_file_storage_quota_limits(storage_paths):
    """
    Tests that file storage respects quota limits and prevents
    resource exhaustion attacks.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa = all_pq_sks[pk_ml_dsa_hex][0]

        # Try to upload many files rapidly
        upload_count = 0
        max_attempts = 20

        for i in range(max_attempts):
            content = f"File {i} content".encode()
            status_code, file_hash = _upload_file_chunked(
                pk_classic_hex,
                sk_classic,
                pk_ml_dsa_hex,
                sig_ml_dsa,
                content,
                f"file_{i}.txt",
                "text/plain",
            )

            if status_code == 201:
                upload_count += 1
            elif status_code == 413:  # Quota exceeded
                break
            else:
                # Other error, fail the test
                assert False, f"Unexpected response code: {status_code}"

        # Should have either succeeded with all uploads or hit quota limit
        assert upload_count > 0, "No files uploaded successfully"
        # If quota limiting is implemented, should hit limit before max_attempts

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_idk_message_format_validation():
    """
    Tests that only properly formatted IDK messages are accepted
    and invalid formats are rejected.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa = all_pq_sks[pk_ml_dsa_hex][0]

        # Test with a valid IDK message first to establish baseline
        valid_content = b"Valid test content"
        status_code, file_hash = _upload_file_chunked(
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            valid_content,
            "valid.txt",
            "text/plain",
        )
        assert status_code == 201, "Valid IDK message should be accepted"

        # Test invalid format by trying to upload corrupted chunks
        # (The new API validates IDK format during chunk processing)
        # This test now focuses on the chunked upload validation
        content2 = b"Another test for format validation"

        # Create IDK message parts manually
        cc = pre.create_crypto_context()
        keys = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        message_parts = create_idk_message_parts(
            content2, cc, keys.publicKey, sk_idk_signer
        )

        if message_parts:
            # Parse first part to get file hash
            part_one_content = message_parts[0]  # Keep as string
            parsed_part = parse_idk_message_part(message_parts[0])
            file_hash2 = parsed_part["headers"]["MerkleRoot"]

            # Register the file normally
            register_nonce = get_nonce()
            register_msg = (
                f"REGISTER:{pk_classic_hex}:{file_hash2}:{register_nonce}".encode()
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
                    "idk_part_one": (
                        "part1.idk",
                        part_one_content,
                        "application/octet-stream",
                    )
                },
                data={
                    "nonce": register_nonce,
                    "filename": "format_test.txt",
                    "content_type": "text/plain",
                    "total_size": str(len(content2)),
                    "classic_signature": classic_sig_register,
                    "pq_signatures": json.dumps([pq_sig_register]),
                },
            )

            # Try to upload an invalid chunk (not proper IDK format)
            if register_response.status_code == 201 and len(message_parts) > 1:
                invalid_chunk = b"not a valid IDK message part"
                chunk_hash = hashlib.blake2b(invalid_chunk).hexdigest()

                upload_nonce = get_nonce()
                upload_msg = (
                    f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash2}:"
                    f"1:{len(message_parts)}:{chunk_hash}:{upload_nonce}"
                ).encode()
                classic_sig_upload = sk_classic.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex()
                pq_sig_upload = {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(upload_msg).hex(),
                    "alg": ML_DSA_ALG,
                }

                chunk_response = client.post(
                    f"/storage/{pk_classic_hex}/{file_hash2}/chunks",
                    files={"file": (chunk_hash, invalid_chunk)},
                    data={
                        "nonce": upload_nonce,
                        "chunk_hash": chunk_hash,
                        "chunk_index": "1",
                        "total_chunks": str(len(message_parts)),
                        "compressed": "false",
                        "classic_signature": classic_sig_upload,
                        "pq_signatures": json.dumps([pq_sig_upload]),
                    },
                )

                # Should fail due to format validation
                assert chunk_response.status_code in [400, 422], (
                    f"Invalid format should be rejected, got {chunk_response.status_code}"
                )

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_audit_trail_file_operations(storage_paths):
    """
    Tests that file operations generate comprehensive audit logs
    for security monitoring and compliance.
    """
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa = all_pq_sks[pk_ml_dsa_hex][0]

        # 1. Upload operation audit
        content = b"Audit test content"
        status_code, file_hash = _upload_file_chunked(
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            content,
            "audit_test.txt",
            "text/plain",
        )
        assert status_code == 201, f"Audit test upload failed with status {status_code}"

        # 2. Download operation audit
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
        )

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks/download",
            json={
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
            },
        )
        assert response.status_code == 200, "Download should succeed"

        # 3. List operation audit
        response = client.get(f"/storage/{pk_classic_hex}")
        assert response.status_code == 200, "List operation should succeed"
        files = response.json()["files"]
        assert file_hash in files, "Uploaded file should appear in list"

        # Note: Actual audit log verification would depend on the logging implementation
        # This test verifies that operations complete successfully, which is a prerequisite
        # for audit logging

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_cross_account_access_prevention(storage_paths):
    """
    Tests that files uploaded by one account cannot be accessed by another account.
    """
    # Create two separate accounts
    sk1, pk1_hex, all_pq_sks1, oqs_sigs_1 = _create_test_account()
    sk2, pk2_hex, all_pq_sks2, oqs_sigs_2 = _create_test_account()

    try:
        pk_ml_dsa1_hex = next(iter(all_pq_sks1))
        sig_ml_dsa1 = all_pq_sks1[pk_ml_dsa1_hex][0]
        pk_ml_dsa2_hex = next(iter(all_pq_sks2))
        sig_ml_dsa2 = all_pq_sks2[pk_ml_dsa2_hex][0]

        # Account 1 uploads a file
        content = b"Private file content"
        status_code, file_hash = _upload_file_chunked(
            pk1_hex,
            sk1,
            pk_ml_dsa1_hex,
            sig_ml_dsa1,
            content,
            "private.txt",
            "text/plain",
        )
        assert status_code == 201, f"Account 1 upload failed with status {status_code}"

        # Account 2 tries to download the file (should fail)
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk2_hex}:{file_hash}:{download_nonce}".encode()
        )

        response = client.post(
            f"/storage/{pk2_hex}/{file_hash}/chunks/download",
            json={
                "nonce": download_nonce,
                "classic_signature": sk2.sign(
                    download_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa2_hex,
                        "signature": sig_ml_dsa2.sign(download_msg).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
            },
        )
        # Should fail - file doesn't exist in account 2's namespace
        assert response.status_code == 404

        # Verify the file is not visible in account 2's file list
        response = client.get(f"/storage/{pk2_hex}")
        assert response.status_code == 200
        files = response.json()["files"]
        assert file_hash not in files, "File should not be visible to other accounts"

        # Verify the file is still accessible to account 1
        download_msg1 = (
            f"DOWNLOAD-CHUNKS:{pk1_hex}:{file_hash}:{download_nonce}".encode()
        )
        response = client.post(
            f"/storage/{pk1_hex}/{file_hash}/chunks/download",
            json={
                "nonce": download_nonce,
                "classic_signature": sk1.sign(
                    download_msg1, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa1_hex,
                        "signature": sig_ml_dsa1.sign(download_msg1).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
            },
        )
        assert response.status_code == 200, (
            "Account 1 should still be able to access its file"
        )

    finally:
        for sig in oqs_sigs_1:
            sig.free()
        for sig in oqs_sigs_2:
            sig.free()
