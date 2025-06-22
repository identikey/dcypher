import ecdsa
import hashlib
import oqs
import pytest
import time
import os
import json
from unittest import mock
from fastapi.testclient import TestClient
from main import app
from app_state import state, get_app_state
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


def test_upload_chunks_successful(storage_paths):
    """
    Tests the successful upload of multiple file chunks after registering the
    main file metadata.
    """
    _, chunk_store_root = storage_paths
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

        # 6. Upload subsequent chunks (skip the first one already sent)
        total_chunks = len(all_pieces)
        for i, chunk_data in enumerate(all_pieces[1:], start=1):
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
                files={"file": (f"chunk_{i}", chunk_data)},
                data={
                    "nonce": chunk_nonce,
                    "chunk_hash": chunk_hash,
                    "chunk_index": str(i),
                    "total_chunks": str(total_chunks),
                    "classic_signature": classic_sig_chunk,
                    "pq_signatures": json.dumps([pq_sig_chunk]),
                },
            )

            assert response.status_code == 200, response.text
            assert (
                f"Chunk {i}/{total_chunks} uploaded successfully"
                in response.json()["message"]
            )

            # Verify chunk exists on server
            chunk_path = os.path.join(chunk_store_root, chunk_hash)
            assert os.path.exists(chunk_path)
            with open(chunk_path, "rb") as f:
                assert f.read() == chunk_data

        # 7. Verify chunk metadata is stored
        # The number of chunks in the store should be one less than total pieces,
        # since the first piece was part of the block store registration.
        if total_chunks > 1:
            assert file_hash in state.chunk_store
            assert len(state.chunk_store[file_hash]) == total_chunks - 1
        else:
            # If there's only one chunk, it was sent with the registration,
            # so the separate chunk_store should not have an entry for it.
            assert file_hash not in state.chunk_store
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


def test_list_files_nonexistent_account():
    """
    Tests that listing files for a non-existent account returns 404.
    """
    response = client.get("/storage/nonexistent-public-key")
    assert response.status_code == 404
    assert "Account not found" in response.json()["detail"]


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


def test_get_file_metadata_nonexistent_file():
    """
    Tests that getting metadata for a non-existent file hash returns 404.
    """
    # 1. Create a real account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        # 2. Attempt to get metadata for a hash that does not exist
        response = client.get(f"/storage/{pk_classic_hex}/nonexistent-file-hash")
        assert response.status_code == 404
        assert "File not found" in response.json()["detail"]
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
