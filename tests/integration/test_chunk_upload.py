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
    _create_test_idk_file,
)

client = TestClient(app)


def test_upload_chunks_successful(storage_paths):
    """
    Tests the successful upload of multiple file chunks after registering the
    main file metadata.
    """
    block_store_root, chunk_store_root = storage_paths
    # 1. Create an account
    (
        sk_classic,
        pk_classic_hex,
        all_pq_sks,
        oqs_sigs_to_free,
    ) = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Prepare all cryptographic materials and content on the client side.
        original_content = (
            b"This is a test file that will be chunked into multiple pieces."
        )
        cc = pre.create_crypto_context()
        keys = pre.generate_keys(cc)
        sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        # 3. Create all the IDK message parts.
        #    This generates the encrypted pieces and the overall Merkle root.
        message_parts = create_idk_message_parts(
            data=original_content,
            cc=cc,
            pk=keys.publicKey,
            signing_key=sk_idk_signer,
        )
        parsed_first_part = parse_idk_message_part(message_parts[0])
        file_hash = parsed_first_part["headers"]["MerkleRoot"]

        # 4. Register the file by sending the *first part* of the message.
        #    The server will store this part and register the file hash.
        registration_idk_part = message_parts[0].encode("utf-8")
        register_nonce = get_nonce()
        register_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        classic_sig_register = sk_classic.sign(
            register_msg, hashfunc=hashlib.sha256
        ).hex()
        pq_sig_register = {
            "public_key": pk_ml_dsa_hex,
            "signature": sig_ml_dsa.sign(register_msg).hex(),
            "alg": ML_DSA_ALG,
        }
        register_response = client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("chunked_file.txt", registration_idk_part, "text/plain")},
            data={
                "nonce": register_nonce,
                "file_hash": file_hash,
                "classic_signature": classic_sig_register,
                "pq_signatures": json.dumps([pq_sig_register]),
            },
        )
        assert register_response.status_code == 201, register_response.text

        # 5. Extract the raw encrypted pieces from the remaining parts to upload as chunks.
        #    This simulates a client holding onto the raw pieces.
        all_pieces = []
        for part_str in message_parts:
            parsed = parse_idk_message_part(part_str)
            piece_bytes = base64.b64decode(parsed["payload_b64"])
            all_pieces.append(piece_bytes)

        # 6. Upload subsequent chunks (skip the first one already sent) with compression
        total_chunks = len(all_pieces)
        for i, chunk_data in enumerate(all_pieces[1:], start=1):
            # Compress the chunk data with maximum compression (simulate small chunks for best compression)
            compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)

            # Hash is calculated on the ORIGINAL (uncompressed) data
            chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
            chunk_nonce = get_nonce()
            chunk_msg = (
                f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:"
                f"{i}:{total_chunks}:{chunk_hash}:{chunk_nonce}"
            ).encode()

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
                files={"file": (f"chunk_{i}", compressed_chunk_data)},
                data={
                    "nonce": chunk_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(total_chunks),
                    "compressed": "true",  # Indicate chunk is compressed
                    "classic_signature": classic_sig_chunk,
                    "pq_signatures": json.dumps([pq_sig_chunk]),
                },
            )

            assert response.status_code == 200, response.text
            assert (
                f"Chunk {i}/{total_chunks} uploaded successfully"
                in response.json()["message"]
            )
            # Check for compression info in response
            assert "compressed" in response.json()["message"]

            # Verify compressed chunk exists on server (individual storage)
            chunk_path = os.path.join(chunk_store_root, chunk_hash)
            assert os.path.exists(chunk_path)
            with open(chunk_path, "rb") as f:
                stored_data = f.read()
                assert stored_data == compressed_chunk_data  # Should be compressed
                # Verify we can decompress it back to original
                assert gzip.decompress(stored_data) == chunk_data

        # 7. Verify chunk metadata is stored and concatenated file exists
        # The number of chunks in the store should be one less than total pieces,
        # since the first piece was part of the block store registration.
        if total_chunks > 1:
            assert file_hash in state.chunk_store
            assert len(state.chunk_store[file_hash]) == total_chunks - 1

            # Verify concatenated file exists (chunks are now stored in block_store_root)
            concatenated_file_path = os.path.join(
                block_store_root, f"{file_hash}.chunks.gz"
            )
            assert os.path.exists(concatenated_file_path), (
                "Concatenated chunks file should exist"
            )
        else:
            # If there's only one chunk, it was sent with the registration,
            # so the separate chunk_store should not have an entry for it.
            assert file_hash not in state.chunk_store
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_chunk_compression_ratio(storage_paths):
    """
    Tests that chunk compression provides significant space savings for small, compressible chunks.
    """
    _, chunk_store_root = storage_paths
    # 1. Create an account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Register a file to get a valid file_hash
        original_content = b"A" * 1000  # 1KB of repeated 'A's - highly compressible
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        register_nonce = get_nonce()
        register_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("test_file.txt", idk_file_bytes, "text/plain")},
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

        # 3. Create a highly compressible chunk
        chunk_data = (
            b"This is a repeating pattern! " * 50
        )  # ~1.5KB, highly compressible
        compressed_chunk_data = gzip.compress(chunk_data, compresslevel=9)

        # Calculate compression ratio
        compression_ratio = len(compressed_chunk_data) / len(chunk_data)
        print(
            f"Compression ratio: {compression_ratio:.2f} ({len(chunk_data)} -> {len(compressed_chunk_data)} bytes)"
        )

        # 4. Upload the compressed chunk
        chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
        chunk_nonce = get_nonce()
        chunk_msg = (
            f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:0:1:{chunk_hash}:{chunk_nonce}"
        ).encode()

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
                "chunk_index": "0",
                "total_chunks": "1",
                "compressed": "true",
                "classic_signature": classic_sig_chunk,
                "pq_signatures": json.dumps([pq_sig_chunk]),
            },
        )

        # 5. Verify successful upload with compression info
        assert response.status_code == 200, response.text
        response_msg = response.json()["message"]
        assert "compressed" in response_msg
        assert (
            f"{len(compressed_chunk_data)} bytes from {len(chunk_data)} bytes"
            in response_msg
        )

        # 6. Verify chunk stored correctly and compression ratio is good
        assert compression_ratio < 0.05, (
            f"Expected compression ratio < 0.05, got {compression_ratio:.2f}"
        )

        # 7. Verify chunk metadata includes compression info
        assert file_hash in state.chunk_store
        chunk_metadata = state.chunk_store[file_hash][chunk_hash]
        assert chunk_metadata["compressed"] is True
        assert chunk_metadata["size"] == len(chunk_data)  # Original size
        assert chunk_metadata["compressed_size"] == len(compressed_chunk_data)

    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_chunk_unauthorized(storage_paths):
    """
    Tests that uploading a file chunk with an invalid signature fails.
    """
    # 1. Create a real account and register a file
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
        # Register a file to get a valid file_hash
        original_content = b"some content"
        idk_file_bytes, file_hash = _create_test_idk_file(original_content)
        register_nonce = get_nonce()
        register_msg = f"UPLOAD:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        client.post(
            f"/storage/{pk_classic_hex}",
            files={"file": ("chunked_file.txt", idk_file_bytes, "text/plain")},
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

        # 2. Attempt to upload a chunk with an invalid signature
        chunk_data = b"chunk data"
        chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
        chunk_nonce = get_nonce()
        # The classic signature will be over an incorrect message
        incorrect_msg = b"this is the wrong message"
        invalid_classic_sig = sk_classic.sign(
            incorrect_msg, hashfunc=hashlib.sha256
        ).hex()
        # The PQ sig is correct, to isolate the failure point
        correct_chunk_msg = (
            f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:0:1:{chunk_hash}:{chunk_nonce}"
        ).encode()
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
                "chunk_index": "0",
                "total_chunks": "1",
                "compressed": "false",  # Add compression parameter
                "classic_signature": invalid_classic_sig,
                "pq_signatures": json.dumps([pq_sig_chunk]),
            },
        )

        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_upload_chunk_for_unregistered_file():
    """
    Tests that uploading a chunk for a file that has not been registered fails.
    """
    # 1. Create a real account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        # 2. Attempt to upload a chunk without registering the parent file hash first
        chunk_data = b"some data"
        response = client.post(
            f"/storage/{pk_classic_hex}/unregistered-file-hash/chunks",
            files={"file": ("chunk_0", chunk_data)},
            data={
                "nonce": get_nonce(),
                "chunk_hash": hashlib.sha256(chunk_data).hexdigest(),
                "chunk_index": "0",
                "total_chunks": "1",
                "compressed": "false",  # Add compression parameter
                "classic_signature": "doesnt-matter",
                "pq_signatures": "doesnt-matter",
            },
        )
        assert response.status_code == 404
        assert "File record not found" in response.json()["detail"]
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()
