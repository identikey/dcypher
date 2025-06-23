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
    _create_test_idk_file_parts,
)

client = TestClient(app)


@pytest.fixture
def setup_uploaded_file(storage_paths):
    """A fixture to set up a fully uploaded file with chunks for download tests."""
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    pk_ml_dsa_hex = next(iter(all_pq_sks))
    sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

    original_content = (
        b"This is a test file for downloading, with enough content to create multiple chunks."
        * 250
    )
    idk_parts, file_hash = _create_test_idk_file_parts(original_content)
    part_one = idk_parts[0]
    data_chunks = idk_parts[1:]

    # Register the file
    register_nonce = get_nonce()
    register_msg = f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
    register_response = client.post(
        f"/storage/{pk_classic_hex}/register",
        files={
            "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
        },
        data={
            "nonce": register_nonce,
            "filename": "download_test.txt",
            "content_type": "text/plain",
            "total_size": str(len(original_content)),
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
    assert register_response.status_code == 201

    # Upload subsequent chunks
    uploaded_chunks_info = []
    for i, chunk_content in enumerate(data_chunks, start=1):
        chunk_bytes = chunk_content.encode("utf-8")
        chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()
        chunk_nonce = get_nonce()
        chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()

        chunk_response = client.post(
            f"/storage/{pk_classic_hex}/{file_hash}/chunks",
            files={"file": (f"chunk_{i}", chunk_bytes, "application/octet-stream")},
            data={
                "nonce": chunk_nonce,
                "chunk_hash": chunk_hash,
                "chunk_index": str(i),
                "total_chunks": str(len(idk_parts)),
                "compressed": "false",
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
        assert chunk_response.status_code == 200
        uploaded_chunks_info.append({"hash": chunk_hash, "original_data": chunk_bytes})

    # The full IDK file content is needed for verification after download
    full_idk_file = "".join(idk_parts)

    yield {
        "sk_classic": sk_classic,
        "pk_classic_hex": pk_classic_hex,
        "all_pq_sks": all_pq_sks,
        "file_hash": file_hash,
        "original_content": original_content,
        "full_idk_file": full_idk_file.encode("utf-8"),
        "uploaded_chunks": uploaded_chunks_info,
        "total_chunks": len(idk_parts),
    }

    # Cleanup
    for sig in oqs_sigs_to_free:
        sig.free()


def test_download_file_successful(setup_uploaded_file):
    """Tests the successful download of a whole file after chunked upload."""
    data = setup_uploaded_file
    sk_classic, pk_classic_hex, all_pq_sks, file_hash = (
        data["sk_classic"],
        data["pk_classic_hex"],
        data["all_pq_sks"],
        data["file_hash"],
    )
    pk_ml_dsa_hex = next(iter(all_pq_sks))
    sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

    download_nonce = get_nonce()
    download_msg = (
        f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
    )
    classic_sig_download = sk_classic.sign(download_msg, hashfunc=hashlib.sha256).hex()
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

    # This endpoint does not exist anymore. We should download the concatenated file.
    # The test for downloading individual chunks is separate.
    download_response = client.post(
        f"/storage/{pk_classic_hex}/{file_hash}/chunks/download",
        json=download_payload,
    )

    assert download_response.status_code == 200, download_response.text
    # We can't easily verify the content of the concatenated Gzip file byte-for-byte,
    # but we can verify its headers and that it's a valid Gzip file.
    assert download_response.headers["content-type"] == "application/gzip"


def test_download_file_unauthorized(setup_uploaded_file):
    """Tests that file download fails if the signatures are invalid."""
    data = setup_uploaded_file
    sk_classic, pk_classic_hex, all_pq_sks, file_hash = (
        data["sk_classic"],
        data["pk_classic_hex"],
        data["all_pq_sks"],
        data["file_hash"],
    )
    pk_ml_dsa_hex = next(iter(all_pq_sks))
    sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

    download_nonce = get_nonce()
    incorrect_msg = b"wrong message for download"
    invalid_sig = sk_classic.sign(incorrect_msg, hashfunc=hashlib.sha256).hex()
    correct_download_msg = (
        f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{file_hash}:{download_nonce}".encode()
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
        f"/storage/{pk_classic_hex}/{file_hash}/chunks/download",
        json=download_payload,
    )
    assert response.status_code == 401
    assert "Invalid classic signature" in response.text


def test_download_file_nonexistent():
    """Tests that downloading a non-existent file returns a 404 error."""
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        fake_file_hash = "nonexistent-file-hash-12345"
        download_nonce = get_nonce()
        download_msg = f"DOWNLOAD-CHUNKS:{pk_classic_hex}:{fake_file_hash}:{download_nonce}".encode()
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
            f"/storage/{pk_classic_hex}/{fake_file_hash}/chunks/download",
            json=download_payload,
        )
        assert response.status_code == 404
        assert "File not found" in response.text
    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_download_file_compressed(setup_uploaded_file):
    """This test is now covered by test_download_chunk_compressed, as whole-file compression is a client concern."""
    pass


def test_download_chunk_compressed(setup_uploaded_file):
    """Tests downloading individual chunks with compression handling."""
    data = setup_uploaded_file
    sk_classic, pk_classic_hex, all_pq_sks, file_hash = (
        data["sk_classic"],
        data["pk_classic_hex"],
        data["all_pq_sks"],
        data["file_hash"],
    )
    pk_ml_dsa_hex = next(iter(all_pq_sks))
    sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

    # We will re-upload one chunk with compression to test this feature
    chunk_to_compress = data["uploaded_chunks"][0]
    original_chunk_data = chunk_to_compress["original_data"]
    compressed_chunk_data = gzip.compress(original_chunk_data, compresslevel=9)
    chunk_hash = chunk_to_compress["hash"]
    total_chunks = data["total_chunks"]
    chunk_index = 1

    chunk_nonce = get_nonce()
    chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_index}:{total_chunks}:{chunk_hash}:{chunk_nonce}".encode()

    response = client.post(
        f"/storage/{pk_classic_hex}/{file_hash}/chunks",
        files={
            "file": ("chunk_1_compressed", compressed_chunk_data, "application/gzip")
        },
        data={
            "nonce": chunk_nonce,
            "chunk_hash": chunk_hash,
            "chunk_index": str(chunk_index),
            "total_chunks": str(total_chunks),
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
    assert response.status_code == 200

    # Test 1: Download compressed chunk as compressed
    download_nonce = get_nonce()
    download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_hash}:{download_nonce}".encode()
    download_payload = {
        "chunk_hash": chunk_hash,
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
        "compressed": True,
    }

    response = client.post(
        f"/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
        json=download_payload,
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/gzip"
    assert response.content == compressed_chunk_data

    # Test 2: Download compressed chunk as decompressed
    download_nonce = get_nonce()
    download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_hash}:{download_nonce}".encode()
    download_payload = {
        "chunk_hash": chunk_hash,
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
        "compressed": False,
    }
    response = client.post(
        f"/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
        json=download_payload,
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.content == original_chunk_data


def test_download_chunk_unauthorized(setup_uploaded_file):
    """Tests that chunk download fails with invalid signatures."""
    data = setup_uploaded_file
    sk_classic, pk_classic_hex, all_pq_sks, file_hash = (
        data["sk_classic"],
        data["pk_classic_hex"],
        data["all_pq_sks"],
        data["file_hash"],
    )
    pk_ml_dsa_hex = next(iter(all_pq_sks))
    sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
    chunk_hash = data["uploaded_chunks"][0]["hash"]

    download_nonce = get_nonce()
    invalid_msg = b"wrong message for chunk download"
    invalid_sig = sk_classic.sign(invalid_msg, hashfunc=hashlib.sha256).hex()
    correct_download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_hash}:{download_nonce}".encode()
    pq_sig_download = {
        "public_key": pk_ml_dsa_hex,
        "signature": sig_ml_dsa.sign(correct_download_msg).hex(),
        "alg": ML_DSA_ALG,
    }

    download_payload = {
        "chunk_hash": chunk_hash,
        "nonce": download_nonce,
        "classic_signature": invalid_sig,
        "pq_signatures": [pq_sig_download],
        "compressed": False,
    }

    response = client.post(
        f"/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
        json=download_payload,
    )
    assert response.status_code == 401
    assert "Invalid classic signature" in response.text


def test_download_chunk_nonexistent(setup_uploaded_file):
    """Tests that downloading a non-existent chunk returns a 404 error."""
    data = setup_uploaded_file
    sk_classic, pk_classic_hex, all_pq_sks, file_hash = (
        data["sk_classic"],
        data["pk_classic_hex"],
        data["all_pq_sks"],
        data["file_hash"],
    )
    pk_ml_dsa_hex = next(iter(all_pq_sks))
    sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

    fake_chunk_hash = "nonexistent-chunk-hash-12345"
    download_nonce = get_nonce()
    download_msg = f"DOWNLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{fake_chunk_hash}:{download_nonce}".encode()
    download_payload = {
        "chunk_hash": fake_chunk_hash,
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
        "compressed": False,
    }

    response = client.post(
        f"/storage/{pk_classic_hex}/{file_hash}/chunks/{fake_chunk_hash}/download",
        json=download_payload,
    )
    assert response.status_code == 404
    assert "Chunk not found" in response.text


def test_concatenated_chunks_download_workflow(setup_uploaded_file):
    """Tests downloading the fully concatenated gzip file."""
    data = setup_uploaded_file
    sk_classic, pk_classic_hex, all_pq_sks, file_hash = (
        data["sk_classic"],
        data["pk_classic_hex"],
        data["all_pq_sks"],
        data["file_hash"],
    )
    pk_ml_dsa_hex = next(iter(all_pq_sks))
    sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

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
        f"/storage/{pk_classic_hex}/{file_hash}/chunks/download", json=download_payload
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/gzip"
    assert "x-chunk-count" in response.headers
    assert int(response.headers["x-chunk-count"]) > 1

    # Basic verification: can gunzip decompress it without error?
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".gz", delete=True) as temp_file:
        temp_file.write(response.content)
        temp_file.flush()
        result = subprocess.run(["gunzip", "-t", temp_file.name], capture_output=True)
        assert result.returncode == 0, f"gunzip test failed: {result.stderr.decode()}"
