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
import io
import requests
from main import app
from app_state import state
from config import ML_DSA_ALG
from src.lib import pre
from src.lib.idk_message import create_idk_message_parts, parse_idk_message_part

from tests.integration.test_api import (
    get_nonce,
    _create_test_idk_file,
    create_test_account_with_keymanager,
)


def test_1mb_file_multiple_encryption_compression(api_base_url: str, tmp_path):
    """
    Tests compression on realistic encrypted chunks by encrypting a 1MB file
    multiple times with different keys, creating many encrypted chunks to test
    compression ratios on actual encrypted data.
    """
    # 1. Create an account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

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
            keys_pre = pre.generate_keys(cc)
            sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

            # Create IDK message parts (encrypted chunks)
            message_parts = create_idk_message_parts(
                data=large_file_content,
                cc=cc,
                pk=keys_pre.publicKey,
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

        # 4. Register a file to associate chunks with.
        # We use the header from the first encryption run to get a valid file_hash.
        part_one_content = all_encrypted_chunks[0][1]
        parsed_part = parse_idk_message_part(part_one_content.decode("utf-8"))
        file_hash = parsed_part["headers"]["MerkleRoot"]
        total_size = len(large_file_content)

        register_nonce = get_nonce(api_base_url)
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
                "filename": "1mb_compression_test.bin",
                "content_type": "application/octet-stream",
                "total_size": str(total_size),
                "classic_signature": classic_sig_register,
                "pq_signatures": json.dumps([pq_sig_register]),
            },
        )
        assert register_response.status_code == 201, register_response.text
        # The first chunk (header) is now uploaded, so we can remove it from our list.
        # Note: The test will re-upload it, which is fine. The goal is to test
        # compression on many chunks, and the server handles duplicate chunks.

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
            chunk_nonce = get_nonce(api_base_url)
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
            response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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
    # OQS signatures are automatically freed when exiting the context


def test_upload_and_download_large_file_chunked(api_base_url: str, tmp_path):
    """
    Tests uploading and downloading a large (1MB) file using the chunked method.
    """
    # 1. Create an account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # 2. Create a large file and its IDK message parts
        large_file_content = os.urandom(1024 * 1024)  # 1MB
        file_size = len(large_file_content)

        # Use a dummy signing key for the IDK message itself, as it's not verified here
        cc = pre.create_crypto_context()
        keys_pre = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        message_parts = create_idk_message_parts(
            data=large_file_content,
            cc=cc,
            pk=keys_pre.publicKey,
            signing_key=sk_idk_signer,
        )
        part_one_content = message_parts[0]
        data_chunks = message_parts[1:]
        total_chunks = len(message_parts)

        parsed_part = parse_idk_message_part(part_one_content)
        file_hash = parsed_part["headers"]["MerkleRoot"]

        # 3. Register the file
        register_nonce = get_nonce(api_base_url)
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
                "filename": "large_file.bin",
                "content_type": "application/octet-stream",
                "total_size": str(file_size),
                "classic_signature": classic_sig_register,
                "pq_signatures": json.dumps([pq_sig_register]),
            },
        )
        assert register_response.status_code == 201, register_response.text

        # 4. Upload the remaining chunks
        for i, chunk_content_str in enumerate(data_chunks):
            chunk_index = i + 1
            chunk_content_bytes = chunk_content_str.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_content_bytes).hexdigest()

            upload_nonce = get_nonce(api_base_url)
            upload_msg = (
                f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:"
                f"{chunk_index}:{total_chunks}:{chunk_hash}:{upload_nonce}"
            ).encode()
            classic_sig_upload = sk_classic.sign(
                upload_msg, hashfunc=hashlib.sha256
            ).hex()
            pq_sig_upload = {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(upload_msg).hex(),
                "alg": ML_DSA_ALG,
            }

            print(
                f"Uploading chunk {chunk_index}/{total_chunks}, hash: {chunk_hash[:12]}..."
            )
            upload_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={"file": (chunk_hash, chunk_content_bytes)},
                data={
                    "nonce": upload_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(chunk_index),
                    "total_chunks": str(total_chunks),
                    "compressed": "false",
                    "classic_signature": classic_sig_upload,
                    "pq_signatures": json.dumps([pq_sig_upload]),
                },
            )
            assert upload_response.status_code == 200, upload_response.text
            print(f"✓ Chunk {chunk_index} uploaded successfully")

        # 5. Download the reconstructed file (via concatenated chunks endpoint)
        download_nonce = get_nonce(api_base_url)
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
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
        download_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/download",
            json=download_payload,
        )

        # 6. Assert success and verify content
        assert download_response.status_code == 200, download_response.text

        # Reconstruct the original full IDK message from the server's gzipped chunks
        reconstructed_parts = []
        data_stream = io.BytesIO(download_response.content)
        gzip_member_count = 0

        # Properly parse concatenated gzip stream
        while data_stream.tell() < len(download_response.content):
            try:
                # Read one complete gzip member
                with gzip.GzipFile(fileobj=data_stream) as gz:
                    decompressed_content = gz.read().decode("utf-8")
                    reconstructed_parts.append(decompressed_content)
                    gzip_member_count += 1
            except Exception as e:
                print(f"Error reading gzip member {gzip_member_count}: {e}")
                break

        print(f"Successfully decompressed {gzip_member_count} gzip members")
        print(f"Expected: {total_chunks} IDK message parts (concatenated)")

        # The new streaming implementation concatenates all IDK parts into a single gzip member,
        # filtering out the newline separators, so we expect exactly 1 gzip member
        assert gzip_member_count == 1, (
            f"Expected 1 concatenated gzip member, got {gzip_member_count}"
        )

        # Concatenate all reconstructed parts to form the complete IDK message
        reconstructed_idk_message = "".join(reconstructed_parts)
        original_idk_message = "\n".join(message_parts)

        # Verify the reconstructed message matches the original
        assert reconstructed_idk_message == original_idk_message, (
            "Reconstructed IDK message doesn't match original"
        )

        print("✓ Concatenated file format and reconstruction test passed!")
    # OQS signatures are automatically freed when exiting the context


def test_concatenated_file_format_and_reconstruction(api_base_url: str, tmp_path):
    """
    Tests that the concatenated gzip file format correctly preserves newline separators
    between IDK message parts and that reconstruction works properly.
    """
    # 1. Create an account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # 2. Create a small file that will generate exactly 3 IDK message parts
        # This gives us a predictable test case
        small_file_content = os.urandom(
            pre.get_slot_count(pre.create_crypto_context()) * 4 + 100
        )

        cc = pre.create_crypto_context()
        keys_pre = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        message_parts = create_idk_message_parts(
            data=small_file_content,
            cc=cc,
            pk=keys_pre.publicKey,
            signing_key=sk_idk_signer,
        )

        # Ensure we have multiple parts for this test
        assert len(message_parts) >= 3, (
            f"Expected at least 3 parts, got {len(message_parts)}"
        )

        part_one_content = message_parts[0]
        data_chunks = message_parts[1:]
        total_chunks = len(message_parts)

        parsed_part = parse_idk_message_part(part_one_content)
        file_hash = parsed_part["headers"]["MerkleRoot"]

        # 3. Register the file
        register_nonce = get_nonce(api_base_url)
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
                "filename": "test_format.bin",
                "content_type": "application/octet-stream",
                "total_size": str(len(small_file_content)),
                "classic_signature": classic_sig_register,
                "pq_signatures": json.dumps([pq_sig_register]),
            },
        )
        assert register_response.status_code == 201, register_response.text

        # 4. Upload the remaining chunks
        for i, chunk_content_str in enumerate(data_chunks):
            chunk_index = i + 1
            chunk_content_bytes = chunk_content_str.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_content_bytes).hexdigest()

            upload_nonce = get_nonce(api_base_url)
            upload_msg = (
                f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:"
                f"{chunk_index}:{total_chunks}:{chunk_hash}:{upload_nonce}"
            ).encode()
            classic_sig_upload = sk_classic.sign(
                upload_msg, hashfunc=hashlib.sha256
            ).hex()
            pq_sig_upload = {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(upload_msg).hex(),
                "alg": ML_DSA_ALG,
            }

            upload_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
                files={"file": (chunk_hash, chunk_content_bytes)},
                data={
                    "nonce": upload_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(chunk_index),
                    "total_chunks": str(total_chunks),
                    "compressed": "false",
                    "classic_signature": classic_sig_upload,
                    "pq_signatures": json.dumps([pq_sig_upload]),
                },
            )
            assert upload_response.status_code == 200, upload_response.text

        # 5. Download the concatenated chunks
        download_nonce = get_nonce(api_base_url)
        download_msg = (
            f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
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
        download_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/download",
            json=download_payload,
        )
        assert download_response.status_code == 200, download_response.text

        # 6. Test the specific reconstruction logic
        reconstructed_parts = []
        data_stream = io.BytesIO(download_response.content)
        gzip_member_count = 0

        # Properly parse concatenated gzip stream
        while data_stream.tell() < len(download_response.content):
            try:
                # Read one complete gzip member
                with gzip.GzipFile(fileobj=data_stream) as gz:
                    decompressed_content = gz.read().decode("utf-8")
                    reconstructed_parts.append(decompressed_content)
                    gzip_member_count += 1
            except Exception as e:
                print(f"Error reading gzip member {gzip_member_count}: {e}")
                break

        print(f"Successfully decompressed {gzip_member_count} gzip members")
        print(f"Expected: {total_chunks} IDK message parts (concatenated)")

        # The new streaming implementation concatenates all IDK parts into a single gzip member,
        # filtering out the newline separators, so we expect exactly 1 gzip member
        assert gzip_member_count == 1, (
            f"Expected 1 concatenated gzip member, got {gzip_member_count}"
        )

        # Concatenate all reconstructed parts to form the complete IDK message
        reconstructed_idk_message = "".join(reconstructed_parts)
        original_idk_message = "\n".join(message_parts)

        # Verify the reconstructed message matches the original
        assert reconstructed_idk_message == original_idk_message, (
            "Reconstructed IDK message doesn't match original"
        )

        print("✓ Concatenated file format and reconstruction test passed!")
