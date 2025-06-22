"""
Large file handling API tests.

This module contains tests for large file operations including
upload/download of large files and compression tests with encrypted data.
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
    _create_test_idk_file,
)

client = TestClient(app)


def test_1mb_file_multiple_encryption_compression(storage_paths):
    """
    Tests compression on realistic encrypted chunks by encrypting a 1MB file
    multiple times with different keys, creating many encrypted chunks to test
    compression ratios on actual encrypted data.
    """
    _, chunk_store_root = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Create a 1MB file
        large_file_content = os.urandom(1024 * 1024)  # 1MB random data
        print(f"Created 1MB file with {len(large_file_content):,} bytes")

        # 3. Encrypt the same file 3 times with different keys to get different encrypted chunks
        all_encrypted_chunks = []
        encryption_runs = 3

        for run in range(encryption_runs):
            print(f"Encryption run {run + 1}/{encryption_runs}...")

            # Create fresh crypto context and keys for each encryption
            cc = pre.create_crypto_context()
            keys = pre.generate_keys(cc)
            sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

            # Create IDK message parts (encrypted chunks)
            message_parts = create_idk_message_parts(
                data=large_file_content,
                cc=cc,
                pk=keys.publicKey,
                signing_key=sk_idk_signer,
            )

            # Use complete IDK message parts (with headers and formatting)
            for i, part_str in enumerate(message_parts):
                # Convert the full IDK message part string to bytes for compression testing
                part_bytes = part_str.encode("utf-8")
                all_encrypted_chunks.append((f"run{run}_chunk{i}", part_bytes))

        print(
            f"Generated {len(all_encrypted_chunks)} encrypted chunks across {encryption_runs} encryption runs"
        )

        # 4. Register a dummy file for chunk uploads
        dummy_content = b"1MB compression test"
        idk_file_bytes, file_hash = _create_test_idk_file(dummy_content)
        register_nonce = get_nonce()
        register_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("compression_test.txt", idk_file_bytes, "text/plain")},
            data={
                "nonce": register_nonce,
                "file_hash": file_hash,
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

        # 5. Upload all encrypted chunks with compression
        total_original_size = 0
        total_compressed_size = 0
        successful_uploads = 0
        total_chunks = len(all_encrypted_chunks)

        print(f"Testing compression on {total_chunks} encrypted chunks...")

        for i, (chunk_name, chunk_data) in enumerate(all_encrypted_chunks):
            # Compress the encrypted chunk data
            compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)

            # Track sizes
            total_original_size += len(chunk_data)
            total_compressed_size += len(compressed_chunk_data)

            # Calculate hash on original encrypted data
            chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
            chunk_nonce = get_nonce()
            chunk_msg = (
                f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:"
                f"{i}:{total_chunks}:{chunk_hash}:{chunk_nonce}"
            ).encode()

            # Sign the message
            classic_sig_chunk = sk_classic.sign(
                chunk_msg, hashfunc=hashlib.sha256
            ).hex()
            pq_sig_chunk = {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(chunk_msg).hex(),
                "alg": ML_DSA_ALG,
            }

            # Upload the compressed encrypted chunk
            response = client.post(
                f"/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={"file": (chunk_name, compressed_chunk_data)},
                data={
                    "nonce": chunk_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(total_chunks),
                    "compressed": "true",
                    "classic_signature": classic_sig_chunk,
                    "pq_signatures": json.dumps([pq_sig_chunk]),
                },
            )

            if response.status_code == 200:
                successful_uploads += 1
            else:
                print(f"Failed to upload {chunk_name}: {response.text}")

            # Progress report every 20 chunks
            if (i + 1) % 20 == 0:
                current_ratio = total_compressed_size / total_original_size
                print(
                    f"Processed {i + 1}/{total_chunks} chunks. Compression ratio so far: {current_ratio:.3f}"
                )

        # 6. Verify all chunks uploaded successfully
        assert successful_uploads == total_chunks, (
            f"Only {successful_uploads}/{total_chunks} chunks uploaded successfully"
        )

        # 7. Calculate and analyze compression results
        overall_compression_ratio = total_compressed_size / total_original_size
        space_saved_percent = (1 - overall_compression_ratio) * 100

        print(f"\n=== COMPRESSION RESULTS FOR ENCRYPTED DATA ===")
        print(f"  Original 1MB file encrypted {encryption_runs} times")
        print(f"  Total chunks processed: {total_chunks}")
        print(f"  Original encrypted size: {total_original_size:,} bytes")
        print(f"  Compressed size: {total_compressed_size:,} bytes")
        print(f"  Compression ratio: {overall_compression_ratio:.3f}")
        print(f"  Space saved: {space_saved_percent:.1f}%")
        print(f"  Average chunk size: {total_original_size // total_chunks:,} bytes")

        # 8. Verify compression is reasonable for full IDK message parts
        # Full IDK messages should compress well due to headers, base64 encoding, and formatting
        # even though the encrypted payload itself doesn't compress much
        assert overall_compression_ratio < 1.0, (
            "Should achieve compression on IDK message parts"
        )
        assert overall_compression_ratio > 0.2, (
            f"Compression ratio {overall_compression_ratio:.3f} seems too good - check if test is working correctly"
        )
        assert overall_compression_ratio < 0.8, (
            f"Compression ratio {overall_compression_ratio:.3f} seems too poor for IDK message format"
        )

        # 9. Verify chunk store metadata
        assert file_hash in state.chunk_store
        assert len(state.chunk_store[file_hash]) == total_chunks

        # 10. Spot check chunk metadata
        sample_indices = [0, total_chunks // 4, total_chunks // 2, total_chunks - 1]
        for i in sample_indices:
            chunk_name, chunk_data = all_encrypted_chunks[i]
            chunk_hash = hashlib.blake2b(chunk_data).hexdigest()

            if chunk_hash in state.chunk_store[file_hash]:
                chunk_metadata = state.chunk_store[file_hash][chunk_hash]
                assert chunk_metadata["compressed"] is True
                assert chunk_metadata["size"] == len(chunk_data)  # Original size
                assert (
                    chunk_metadata["compressed_size"] < chunk_metadata["size"]
                )  # Some compression

    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_and_download_large_file(storage_paths):
    """
    Tests uploading and downloading a large (1MB) file.
    """
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Create a large file
        large_file_content = os.urandom(1024 * 1024)  # 1MB
        idk_file_bytes, file_hash = _create_test_idk_file(large_file_content)

        # 3. Upload the file
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
            files={
                "file": (
                    "large_file.bin",
                    idk_file_bytes,
                    "application/octet-stream",
                )
            },
            data={
                "nonce": upload_nonce,
                "file_hash": file_hash,
                "classic_signature": classic_sig_upload,
                "pq_signatures": json.dumps([pq_sig_upload]),
            },
        )
        assert upload_response.status_code == 201, upload_response.text

        # 4. Download the file
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

        # 5. Assert success and verify content
        assert download_response.status_code == 200, download_response.text
        assert download_response.content == idk_file_bytes
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()
