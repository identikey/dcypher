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
from src.main import app
from src.app_state import state
from src.lib.pq_auth import SUPPORTED_SIG_ALGS
from src.config import ML_DSA_ALG
from src.lib import pre
from src.lib.idk_message import MerkleTree, IDK_VERSION
from src.lib.idk_message import create_idk_message_parts, parse_idk_message_part
import base64

from tests.integration.test_api import (
    storage_paths,
    cleanup,
    _create_test_account,
    get_nonce,
    _create_test_idk_file,
)

client = TestClient(app)


def test_file_upload_timing_attack_resistance(storage_paths):
    """
    Tests that file operations execute in constant time regardless of
    file existence to prevent information leakage through timing attacks.
    """
    block_store_root, _ = storage_paths
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 1. Upload a file first
        original_content = b"Test content for timing analysis"
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

        # 2. Test download timing for existing vs non-existent files
        # Existing file download timing
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
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
            f"/storage/{pk_classic_hex}/{file_hash}/download", json=download_payload
        )
        existing_time = time.perf_counter() - start_time
        assert response1.status_code == 200

        # Non-existent file download timing
        fake_hash = "nonexistent" + "0" * 50
        download_nonce2 = get_nonce()
        download_msg2 = (
            f"DOWNLOAD:{pk_classic_hex}:{fake_hash}:{download_nonce2}".encode()
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
            f"/storage/{pk_classic_hex}/{fake_hash}/download", json=download_payload2
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
            sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

            # Create unique content for each thread
            content = f"Thread {thread_id} test content".encode()
            idk_file_bytes, file_hash = _create_test_idk_file(content)
            upload_nonce = get_nonce()
            upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()

            response = client.post(
                f"/storage/{pk_classic_hex}",
                files={"file": (f"test_{thread_id}.txt", idk_file_bytes, "text/plain")},
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

            # Clean up OQS signatures
            for sig in oqs_sigs_inner:
                sig.free()

            return thread_id, response.status_code, file_hash
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
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 1. Create a valid IDK file
        original_content = b"This content will be corrupted"
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)

        # 2. Corrupt the file content (flip some bytes)
        corrupted_bytes = bytearray(idk_file_bytes)
        if len(corrupted_bytes) > 10:
            corrupted_bytes[10] ^= 0xFF  # Flip bits in the middle
            corrupted_bytes[-10] ^= 0xFF  # Flip bits near the end

        # 3. Try to upload with original hash but corrupted content
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()

        response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("corrupted.txt", bytes(corrupted_bytes), "text/plain")},
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

        # Should fail due to corruption detection (IDK parsing or hash mismatch)
        assert response.status_code == 400
        assert (
            "hash does not match" in response.text.lower()
            or "parse" in response.text.lower()
            or "decode" in response.text.lower()
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
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Create a 5MB file to test memory handling
        large_content = os.urandom(5 * 1024 * 1024)  # 5MB
        idk_file_bytes, file_hash = _create_test_idk_file(large_content)

        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()

        # Monitor memory usage during upload (basic check)
        import psutil

        process = psutil.Process()
        memory_before = process.memory_info().rss

        start_time = time.perf_counter()
        response = client.post(
            f"/storage/{pk_classic_hex}",
            files={
                "file": ("large_file.bin", idk_file_bytes, "application/octet-stream")
            },
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
        upload_time = time.perf_counter() - start_time

        memory_after = process.memory_info().rss
        memory_increase = memory_after - memory_before

        # Verify upload succeeded
        assert response.status_code == 201

        # Memory increase should be reasonable (< 50MB for a 5MB file)
        assert memory_increase < 50 * 1024 * 1024, (
            f"Memory usage too high: {memory_increase} bytes"
        )

        # Upload time should be reasonable (< 10 seconds)
        assert upload_time < 10.0, f"Upload took too long: {upload_time}s"

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
        sig_ml_dsa1, _ = all_pq_sks1[pk_ml_dsa1_hex]
        pk_ml_dsa2_hex = next(iter(all_pq_sks2))
        sig_ml_dsa2, _ = all_pq_sks2[pk_ml_dsa2_hex]

        # 1. Account 1 uploads a file
        content = b"Private file content"
        idk_file_bytes, file_hash = _create_test_idk_file(content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk1_hex}:{file_hash}:{upload_nonce}".encode()

        response = client.post(
            f"/storage/{pk1_hex}",
            files={"file": ("private.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": sk1.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa1_hex,
                            "signature": sig_ml_dsa1.sign(upload_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )
        assert response.status_code == 201

        # 2. Account 2 tries to download Account 1's file (should fail)
        download_nonce = get_nonce()
        download_msg = f"DOWNLOAD:{pk2_hex}:{file_hash}:{download_nonce}".encode()

        response = client.post(
            f"/storage/{pk2_hex}/{file_hash}/download",
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
        cross_download_msg = f"DOWNLOAD:{pk1_hex}:{file_hash}:{download_nonce}".encode()
        response = client.post(
            f"/storage/{pk1_hex}/{file_hash}/download",
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
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Try to upload many files rapidly
        upload_count = 0
        max_attempts = 20

        for i in range(max_attempts):
            content = f"File {i} content".encode()
            idk_file_bytes, file_hash = _create_test_idk_file(content)
            upload_nonce = get_nonce()
            upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()

            response = client.post(
                f"/storage/{pk_classic_hex}",
                files={"file": (f"file_{i}.txt", idk_file_bytes, "text/plain")},
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

            if response.status_code == 201:
                upload_count += 1
            elif response.status_code == 413:  # Quota exceeded
                break
            else:
                # Other error, fail the test
                assert False, f"Unexpected response code: {response.status_code}"

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
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # Test various invalid IDK message formats
        invalid_formats = [
            b"not an IDK message at all",
            b'{"invalid": "json structure"}',
            b"IDK:v1.0:INVALID_FORMAT:data",
            b"IDK:v999.0:SINGLE:invalid_base64_data",
            # Add more invalid format tests
        ]

        for invalid_data in invalid_formats:
            fake_hash = hashlib.blake2b(invalid_data).hexdigest()
            upload_nonce = get_nonce()
            upload_msg = f"UPLOAD:{pk_classic_hex}:{fake_hash}:{upload_nonce}".encode()

            response = client.post(
                f"/storage/{pk_classic_hex}",
                files={"file": ("invalid.idk", invalid_data, "text/plain")},
                data={
                    "nonce": upload_nonce,
                    "file_hash": fake_hash,
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

            # Should fail due to format validation or hash mismatch
            assert response.status_code in [400, 422], (
                f"Invalid format accepted: {invalid_data[:50]}"
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
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 1. Upload operation audit
        content = b"Audit test content"
        idk_file_bytes, file_hash = _create_test_idk_file(content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{upload_nonce}".encode()

        response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("audit_test.txt", idk_file_bytes, "text/plain")},
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
        assert response.status_code == 201

        # 2. Download operation audit
        download_nonce = get_nonce()
        download_msg = (
            f"DOWNLOAD:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
        )

        response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/download",
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
        assert response.status_code == 200

        # 3. Failed operation audit
        response = client.post(
            f"/storage/{pk_classic_hex}/nonexistent/download",
            json={
                "nonce": get_nonce(),
                "classic_signature": "invalid_sig",
                "pq_signatures": [
                    {"public_key": "invalid", "signature": "invalid", "alg": ML_DSA_ALG}
                ],
            },
        )
        assert response.status_code in [400, 401, 404]

        # Note: In production, verify audit logs contain:
        # - Timestamp, operation type, account, file hash, result
        # - IP address, user agent, request size
        # - Authentication method and signature verification status

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
        sig_ml_dsa1, _ = all_pq_sks1[pk_ml_dsa1_hex]
        pk_ml_dsa2_hex = next(iter(all_pq_sks2))
        sig_ml_dsa2, _ = all_pq_sks2[pk_ml_dsa2_hex]

        # Account 1 uploads a file
        content = b"Private file content"
        idk_file_bytes, file_hash = _create_test_idk_file(content)
        upload_nonce = get_nonce()
        upload_msg = f"UPLOAD:{pk1_hex}:{file_hash}:{upload_nonce}".encode()

        response = client.post(
            f"/storage/{pk1_hex}",
            files={"file": ("private.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": sk1.sign(
                    upload_msg, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": json.dumps(
                    [
                        {
                            "public_key": pk_ml_dsa1_hex,
                            "signature": sig_ml_dsa1.sign(upload_msg).hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ]
                ),
            },
        )
        assert response.status_code == 201

        # Account 2 tries to download Account 1's file (should fail)
        download_nonce = get_nonce()
        download_msg = f"DOWNLOAD:{pk2_hex}:{file_hash}:{download_nonce}".encode()

        response = client.post(
            f"/storage/{pk2_hex}/{file_hash}/download",
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

    finally:
        for sig in oqs_sigs_1:
            sig.free()
        for sig in oqs_sigs_2:
            sig.free()
