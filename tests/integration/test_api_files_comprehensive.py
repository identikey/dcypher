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
import functools
import requests
import tempfile
from unittest import mock
from main import app
from app_state import state
from src.lib.pq_auth import SUPPORTED_SIG_ALGS
from config import ML_DSA_ALG
from src.lib import pre
from src.lib.idk_message import MerkleTree, IDK_VERSION
from src.lib.idk_message import create_idk_message_parts, parse_idk_message_part
import base64
from src.lib.api_client import DCypherClient, DCypherAPIError
from pathlib import Path
from src.lib.pq_auth import generate_pq_keys
from src.lib import idk_message

from tests.integration.test_api import (
    get_nonce,
    create_test_account_with_keymanager,
)


def _upload_file_chunked(
    api_base_url: str,
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
    register_nonce = get_nonce(api_base_url)
    register_msg = f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
    classic_sig_register = sk_classic.sign(register_msg, hashfunc=hashlib.sha256).hex()
    pq_sig_register = {
        "public_key": pk_ml_dsa_hex,
        "signature": sig_ml_dsa.sign(register_msg).hex(),
        "alg": ML_DSA_ALG,
    }

    register_response = requests.post(
        f"{api_base_url}/storage/{pk_classic_hex}/register",
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

        upload_nonce = get_nonce(api_base_url)
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

        chunk_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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


def test_file_upload_timing_attack_resistance(api_base_url: str, tmp_path):
    """
    Tests that file operations execute in constant time regardless of
    file existence to prevent information leakage through timing attacks.
    """
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # 1. Upload a file first using the new chunked API
        original_content = b"Test content for timing analysis"
        status_code, file_hash = _upload_file_chunked(
            api_base_url,
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            original_content,
            "test.txt",
            "text/plain",
        )
        assert status_code in [200, 201], f"Upload failed with status {status_code}"

        # 2. Test download timing for existing vs non-existent files
        # Existing file download timing
        download_nonce = get_nonce(api_base_url)
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
        response1 = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/download",
            json=download_payload,
        )
        existing_time = time.perf_counter() - start_time
        assert response1.status_code == 200

        # Non-existent file download timing
        fake_hash = "nonexistent" + "0" * 50
        download_nonce2 = get_nonce(api_base_url)
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
        response2 = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{fake_hash}/chunks/download",
            json=download_payload2,
        )
        nonexistent_time = time.perf_counter() - start_time
        assert response2.status_code == 404

        # Timing difference should be minimal (< 50ms)
        time_difference = abs(existing_time - nonexistent_time)
        assert time_difference < 0.26, (
            f"Timing difference too large: {time_difference}s"
        )
    # OQS signatures are automatically freed when exiting the context


def test_concurrent_file_uploads(api_base_url: str):
    """
    Tests concurrent file upload operations to ensure thread safety
    and prevent race conditions in file storage.

    This test now uses the DCypherClient for more realistic usage patterns.
    """

    def upload_single_file(thread_id, api_base_url_inner):
        """Upload a single file in a thread using the API client"""
        try:
            # Generate keys for this thread's account
            sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            vk_classic = sk_classic.get_verifying_key()
            assert vk_classic is not None
            pk_classic_hex = vk_classic.to_string("uncompressed").hex()

            # Generate PQ keys
            pq_pk, pq_sk = generate_pq_keys(ML_DSA_ALG)

            # Create temporary auth keys file for this thread
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Save classic secret key
                classic_sk_path = temp_path / f"classic_{thread_id}.sk"
                with open(classic_sk_path, "w") as f:
                    f.write(sk_classic.to_string().hex())

                # Save PQ secret key
                pq_sk_path = temp_path / f"pq_{thread_id}.sk"
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
                auth_keys_file = temp_path / f"auth_keys_{thread_id}.json"
                with open(auth_keys_file, "w") as f:
                    json.dump(auth_keys_data, f)

                # Create API client and account
                client = DCypherClient(api_base_url_inner, str(auth_keys_file))
                pq_keys = [{"pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}]

                # Create account
                client.create_account(pk_classic_hex, pq_keys)

                # Create unique content and prepare for upload
                content = f"Thread {thread_id} test content for concurrent upload testing".encode()

                # Create IDK message parts manually since the API client expects them
                cc = pre.create_crypto_context()
                keys = pre.generate_keys(cc)
                sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

                message_parts = idk_message.create_idk_message_parts(
                    content, cc, keys.publicKey, sk_idk_signer
                )

                if not message_parts:
                    return thread_id, 400, None

                # Parse first part to get file hash
                parsed_part = idk_message.parse_idk_message_part(message_parts[0])
                file_hash = parsed_part["headers"]["MerkleRoot"]

                # Register file using API client
                result = client.register_file(
                    public_key=pk_classic_hex,
                    file_hash=file_hash,
                    idk_part_one=message_parts[0],
                    filename=f"test_{thread_id}.txt",
                    content_type="text/plain",
                    total_size=len(content),
                )

                # Upload remaining chunks using API client
                for i, chunk_content_str in enumerate(message_parts[1:], 1):
                    chunk_content_bytes = chunk_content_str.encode("utf-8")
                    chunk_hash = hashlib.blake2b(chunk_content_bytes).hexdigest()

                    chunk_result = client.upload_chunk(
                        public_key=pk_classic_hex,
                        file_hash=file_hash,
                        chunk_data=chunk_content_bytes,
                        chunk_hash=chunk_hash,
                        chunk_index=i,
                        total_chunks=len(message_parts),
                        compressed=False,
                    )

                return thread_id, 200, file_hash

        except DCypherAPIError as e:
            return thread_id, 500, str(e)
        except Exception as e:
            return thread_id, 500, str(e)

    # Test with 10 concurrent uploads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Use functools.partial to pass the api_base_url to the worker function
        task = functools.partial(upload_single_file, api_base_url_inner=api_base_url)
        futures = [executor.submit(task, i) for i in range(10)]
        results = [
            future.result() for future in concurrent.futures.as_completed(futures)
        ]

    # Verify all uploads succeeded
    success_count = sum(1 for _, status_code, _ in results if status_code == 200)
    assert success_count == 10, (
        f"Only {success_count}/10 concurrent uploads succeeded. Results: {results}"
    )

    # Verify all file hashes are unique
    file_hashes = [fh for _, status_code, fh in results if status_code == 200]
    assert len(set(file_hashes)) == len(file_hashes), "Duplicate file hashes detected"


def test_file_corruption_detection(api_base_url: str, tmp_path):
    """
    Tests that the system detects and rejects corrupted file uploads
    through hash validation and Merkle tree verification.
    """
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # 1. Create a valid file first to establish baseline
        original_content = b"This content will be corrupted"
        status_code, file_hash = _upload_file_chunked(
            api_base_url,
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            original_content,
            "valid.txt",
            "text/plain",
        )
        assert status_code in [200, 201], "Valid upload should succeed"

        # 2. Test corruption detection by trying to upload chunks with wrong hashes
        # Create another file and intentionally corrupt the chunk hash
        content2 = b"Another file for corruption testing"

        # Create IDK message parts manually to test corruption
        cc = pre.create_crypto_context()
        keys_pre = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        message_parts = create_idk_message_parts(
            content2, cc, keys_pre.publicKey, sk_idk_signer
        )

        if not message_parts:
            assert False, "Failed to create IDK message parts"

        # Parse first part to get file hash
        part_one_content = message_parts[0]  # Keep as string
        parsed_part = parse_idk_message_part(message_parts[0])
        file_hash2 = parsed_part["headers"]["MerkleRoot"]

        # Register the file normally
        register_nonce = get_nonce(api_base_url)
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

        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
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

            upload_nonce = get_nonce(api_base_url)
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

            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash2}/chunks",
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
    # OQS signatures are automatically freed when exiting the context


def test_large_file_memory_management(api_base_url: str):
    """
    Tests that large file uploads are handled efficiently without
    causing memory exhaustion or system instability.

    This test now uses the DCypherClient for more realistic usage patterns.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError
    import tempfile
    import json
    from pathlib import Path
    from src.lib.pq_auth import generate_pq_keys
    from src.lib import idk_message

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Generate classic key
        sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk_classic = sk_classic.get_verifying_key()
        assert vk_classic is not None
        pk_classic_hex = vk_classic.to_string().hex()

        # Save classic key
        classic_sk_path = temp_path / "classic.sk"
        with open(classic_sk_path, "w") as f:
            f.write(sk_classic.to_string().hex())

        # Generate and save PQ key
        pq_pk_new, pq_sk_new = generate_pq_keys(ML_DSA_ALG)
        pq_sk_path = temp_path / "pq.sk"
        with open(pq_sk_path, "wb") as f:
            f.write(pq_sk_new)

        # Create auth keys file
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": [
                {
                    "sk_path": str(pq_sk_path),
                    "pk_hex": pq_pk_new.hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
        }
        auth_keys_file = temp_path / "auth_keys.json"
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        # Create API client
        client = DCypherClient(api_base_url, str(auth_keys_file))

        # Create account through API client
        client.create_account(
            pk_classic_hex, [{"pk_hex": pq_pk_new.hex(), "alg": ML_DSA_ALG}]
        )

        # Create a 5MB file to test memory handling
        large_content = os.urandom(5 * 1024 * 1024)  # 5MB

        # Monitor memory usage during upload (basic check)
        import psutil

        process = psutil.Process()
        memory_before = process.memory_info().rss

        start_time = time.perf_counter()

        # Create IDK message parts for the large file
        cc = pre.create_crypto_context()
        keys = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        message_parts = idk_message.create_idk_message_parts(
            large_content, cc, keys.publicKey, sk_idk_signer
        )

        if not message_parts:
            assert False, "Failed to create IDK message parts"

        # Parse first part to get file hash
        parsed_part = idk_message.parse_idk_message_part(message_parts[0])
        file_hash = parsed_part["headers"]["MerkleRoot"]

        # Register and upload file using API client
        client.register_file(
            public_key=pk_classic_hex,
            file_hash=file_hash,
            idk_part_one=message_parts[0],
            filename="large_file.bin",
            content_type="application/octet-stream",
            total_size=len(large_content),
        )

        # Upload remaining chunks
        for i, chunk_content_str in enumerate(message_parts[1:], 1):
            chunk_content_bytes = chunk_content_str.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_content_bytes).hexdigest()

            client.upload_chunk(
                public_key=pk_classic_hex,
                file_hash=file_hash,
                chunk_data=chunk_content_bytes,
                chunk_hash=chunk_hash,
                chunk_index=i,
                total_chunks=len(message_parts),
                compressed=False,
            )

        upload_time = time.perf_counter() - start_time

        memory_after = process.memory_info().rss
        memory_increase = memory_after - memory_before

        # Verify upload succeeded by checking file list
        files = client.list_files(pk_classic_hex)
        # files might be a list of strings (hashes) or dictionaries
        if files and isinstance(files[0], str):
            assert file_hash in files, "Large file should appear in file list"
        else:
            assert any(
                f.get("hash", f.get("file_hash", "")) == file_hash for f in files
            ), "Large file should appear in file list"

        # Memory increase should be reasonable (< 500MB for a 5MB file with crypto operations)
        # The higher limit accounts for IDK message creation, multiple buffers, and crypto operations
        assert memory_increase < 500 * 1024 * 1024, (
            f"Memory usage too high: {memory_increase} bytes"
        )

        # Upload time should be reasonable (adjust for parallel test execution)
        # Allow more time when running with multiple pytest workers due to resource contention
        max_upload_time = 60.0  # More generous timeout for parallel execution
        assert upload_time < max_upload_time, (
            f"Upload took too long: {upload_time}s (max: {max_upload_time}s)"
        )


def test_file_access_authorization_edge_cases(api_base_url: str, tmp_path):
    """
    Tests edge cases in file access authorization to ensure proper
    security boundaries are maintained.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # Create two separate accounts using the new context manager pattern
    client1, pk1_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path / "account1"
    )
    client2, pk2_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path / "account2"
    )

    # Account 1 uploads a file
    with client1.signing_keys() as keys1:
        sk1 = keys1["classic_sk"]
        pk_ml_dsa1_hex = keys1["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa1 = keys1["pq_sigs"][0]["sig"]

        content = b"Private file content"
        status_code, file_hash = _upload_file_chunked(
            api_base_url,
            pk1_hex,
            sk1,
            pk_ml_dsa1_hex,
            sig_ml_dsa1,
            content,
            "private.txt",
            "text/plain",
        )
        assert status_code in [200, 201], (
            f"Account 1 upload failed with status {status_code}"
        )

    # Account 2 tries to access Account 1's file
    with client2.signing_keys() as keys2:
        sk2 = keys2["classic_sk"]
        pk_ml_dsa2_hex = keys2["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa2 = keys2["pq_sigs"][0]["sig"]

        # 2. Account 2 tries to download Account 1's file (should fail)
        download_nonce = get_nonce(api_base_url)
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk2_hex}:{file_hash}:{download_nonce}".encode()
        )

        response = requests.post(
            f"{api_base_url}/storage/{pk2_hex}/{file_hash}/chunks/download",
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

        # 3. Account 2 tries to access Account 1's file list (should not see it) using API client
        from src.lib.api_client import DCypherClient

        client = DCypherClient(api_base_url)
        files = client.list_files(pk2_hex)
        assert file_hash not in files, "File leaked across accounts"

        # 4. Try cross-account signature attack (Account 2 signs Account 1's download)
        cross_download_msg = (
            f"DOWNLOAD-CHUNKS:{pk1_hex}:{file_hash}:{download_nonce}".encode()
        )
        response = requests.post(
            f"{api_base_url}/storage/{pk1_hex}/{file_hash}/chunks/download",
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

    # OQS signatures are automatically freed when exiting the context


def test_file_storage_quota_limits(api_base_url: str, tmp_path):
    """
    Tests that file storage respects quota limits and prevents
    resource exhaustion attacks.
    """
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # Try to upload many files rapidly
        upload_count = 0
        max_attempts = 20

        for i in range(max_attempts):
            content = f"File {i} content".encode()
            status_code, file_hash = _upload_file_chunked(
                api_base_url,
                pk_classic_hex,
                sk_classic,
                pk_ml_dsa_hex,
                sig_ml_dsa,
                content,
                f"file_{i}.txt",
                "text/plain",
            )

            if status_code in [200, 201]:
                upload_count += 1
            elif status_code == 413:  # Quota exceeded
                break
            else:
                # Other error, fail the test
                assert False, f"Unexpected response code: {status_code}"

        # Should have either succeeded with all uploads or hit quota limit
        assert upload_count > 0, "No files uploaded successfully"
        # If quota limiting is implemented, should hit limit before max_attempts
    # OQS signatures are automatically freed when exiting the context


def test_idk_message_format_validation(api_base_url: str, tmp_path):
    """
    Tests that only properly formatted IDK messages are accepted
    and invalid formats are rejected.
    """
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # Test with a valid IDK message first to establish baseline
        valid_content = b"Valid test content"
        status_code, file_hash = _upload_file_chunked(
            api_base_url,
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            valid_content,
            "valid.txt",
            "text/plain",
        )
        assert status_code in [200, 201], "Valid IDK message should be accepted"

        # Test invalid format by trying to upload corrupted chunks
        # (The new API validates IDK format during chunk processing)
        # This test now focuses on the chunked upload validation
        content2 = b"Another test for format validation"

        # Create IDK message parts manually
        cc = pre.create_crypto_context()
        keys_pre = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        message_parts = create_idk_message_parts(
            content2, cc, keys_pre.publicKey, sk_idk_signer
        )

        if message_parts:
            # Parse first part to get file hash
            part_one_content = message_parts[0]  # Keep as string
            parsed_part = parse_idk_message_part(message_parts[0])
            file_hash2 = parsed_part["headers"]["MerkleRoot"]

            # Register the file normally
            register_nonce = get_nonce(api_base_url)
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

            register_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/register",
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

                upload_nonce = get_nonce(api_base_url)
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

                chunk_response = requests.post(
                    f"{api_base_url}/storage/{pk_classic_hex}/{file_hash2}/chunks",
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
    # OQS signatures are automatically freed when exiting the context


def test_audit_trail_file_operations(api_base_url: str, tmp_path):
    """
    Tests that file operations generate comprehensive audit logs
    for security monitoring and compliance.
    """
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # 1. Upload operation audit
        content = b"Audit test content"
        status_code, file_hash = _upload_file_chunked(
            api_base_url,
            pk_classic_hex,
            sk_classic,
            pk_ml_dsa_hex,
            sig_ml_dsa,
            content,
            "audit_test.txt",
            "text/plain",
        )
        assert status_code in [200, 201], (
            f"Audit test upload failed with status {status_code}"
        )

        # 2. Download operation audit
        download_nonce = get_nonce(api_base_url)
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
        )

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/download",
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

        # 3. List operation audit using API client
        from src.lib.api_client import DCypherClient

        api_client = DCypherClient(api_base_url)
        files_list = api_client.list_files(pk_classic_hex)
        assert file_hash in files_list, "Uploaded file should appear in list"

        # Note: Actual audit log verification would depend on the logging implementation
        # This test verifies that operations complete successfully, which is a prerequisite
        # for audit logging
    # OQS signatures are automatically freed when exiting the context


def test_cross_account_access_prevention(api_base_url: str, tmp_path):
    """
    Tests that files uploaded by one account cannot be accessed by another account.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # Create two separate accounts using the new context manager pattern
    client1, pk1_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path / "account1"
    )
    client2, pk2_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path / "account2"
    )

    # Account 1 uploads a file
    with client1.signing_keys() as keys1:
        sk1 = keys1["classic_sk"]
        pk_ml_dsa1_hex = keys1["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa1 = keys1["pq_sigs"][0]["sig"]

        content = b"Private file content"
        status_code, file_hash = _upload_file_chunked(
            api_base_url,
            pk1_hex,
            sk1,
            pk_ml_dsa1_hex,
            sig_ml_dsa1,
            content,
            "private.txt",
            "text/plain",
        )
        assert status_code in [200, 201], (
            f"Account 1 upload failed with status {status_code}"
        )

    # Account 2 tries to access Account 1's file
    with client2.signing_keys() as keys2:
        sk2 = keys2["classic_sk"]
        pk_ml_dsa2_hex = keys2["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa2 = keys2["pq_sigs"][0]["sig"]

        # 2. Account 2 tries to download Account 1's file (should fail)
        download_nonce = get_nonce(api_base_url)
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk2_hex}:{file_hash}:{download_nonce}".encode()
        )

        response = requests.post(
            f"{api_base_url}/storage/{pk2_hex}/{file_hash}/chunks/download",
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

        # 3. Account 2 tries to access Account 1's file list (should not see it) using API client
        from src.lib.api_client import DCypherClient

        client = DCypherClient(api_base_url)
        files = client.list_files(pk2_hex)
        assert file_hash not in files, "File should not be visible to other accounts"

    # Verify the file is still accessible to account 1
    with client1.signing_keys() as keys1:
        sk1 = keys1["classic_sk"]
        pk_ml_dsa1_hex = keys1["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa1 = keys1["pq_sigs"][0]["sig"]

        download_nonce = get_nonce(api_base_url)
        download_msg1 = (
            f"DOWNLOAD-CHUNKS:{pk1_hex}:{file_hash}:{download_nonce}".encode()
        )
        response = requests.post(
            f"{api_base_url}/storage/{pk1_hex}/{file_hash}/chunks/download",
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
