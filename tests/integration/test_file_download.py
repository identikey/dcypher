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
import requests
import subprocess
import tempfile
import collections
from main import app
from config import ML_DSA_ALG
from lib import pre
from lib.idk_message import create_idk_message_parts, parse_idk_message_part

from tests.integration.test_api import (
    get_nonce,
    _create_test_idk_file_parts,
    setup_uploaded_file,
    create_test_account_with_keymanager,
)


def test_download_file_successful(api_base_url: str):
    """Tests the successful download of a whole file after chunked upload."""
    data = setup_uploaded_file(api_base_url)
    try:
        pk_ml_dsa_hex = next(iter(data.all_pq_sks))
        sig_ml_dsa, _ = data.all_pq_sks[pk_ml_dsa_hex]

        download_nonce = get_nonce(api_base_url)
        download_msg = f"DOWNLOAD-CHUNKS:{data.pk_classic_hex}:{data.file_hash}:{download_nonce}".encode()
        classic_sig_download = data.sk_classic.sign(
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
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks/download",
            json=download_payload,
        )

        assert download_response.status_code == 200, download_response.text
        assert download_response.headers["content-type"] == "application/gzip"
    finally:
        for sig in data.oqs_sigs_to_free:
            sig.free()


def test_download_file_unauthorized(api_base_url: str):
    """Tests that file download fails if the signatures are invalid."""
    data = setup_uploaded_file(api_base_url)
    try:
        pk_ml_dsa_hex = next(iter(data.all_pq_sks))
        sig_ml_dsa, _ = data.all_pq_sks[pk_ml_dsa_hex]

        download_nonce = get_nonce(api_base_url)
        incorrect_msg = b"wrong message for download"
        invalid_sig = data.sk_classic.sign(incorrect_msg, hashfunc=hashlib.sha256).hex()
        correct_download_msg = f"DOWNLOAD-CHUNKS:{data.pk_classic_hex}:{data.file_hash}:{download_nonce}".encode()
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

        response = requests.post(
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks/download",
            json=download_payload,
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    finally:
        for sig in data.oqs_sigs_to_free:
            sig.free()


def test_download_file_nonexistent(api_base_url: str, tmp_path):
    """
    Tests that downloading a non-existent file returns a 404 error.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # Create account using the new KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

        fake_file_hash = "nonexistent-file-hash-12345"
        download_nonce = get_nonce(api_base_url)
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

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{fake_file_hash}/chunks/download",
            json=download_payload,
        )
        assert response.status_code == 404
        assert "File not found" in response.text
    # OQS signatures are automatically freed when exiting the context


def test_download_file_compressed(api_base_url: str):
    """This test is now covered by test_download_chunk_compressed, as whole-file compression is a client concern."""
    pass


def test_download_chunk_compressed(api_base_url: str):
    """Tests downloading individual chunks with compression handling."""
    data = setup_uploaded_file(api_base_url)
    try:
        pk_ml_dsa_hex = next(iter(data.all_pq_sks))
        sig_ml_dsa, _ = data.all_pq_sks[pk_ml_dsa_hex]

        # We will re-upload one chunk with compression to test this feature
        chunk_to_compress = data.uploaded_chunks[0]
        original_chunk_data = chunk_to_compress["original_data"]
        compressed_chunk_data = gzip.compress(original_chunk_data, compresslevel=9)
        chunk_hash = chunk_to_compress["hash"]
        total_chunks = data.total_chunks
        chunk_index = 1

        chunk_nonce = get_nonce(api_base_url)
        chunk_msg = f"UPLOAD-CHUNK:{data.pk_classic_hex}:{data.file_hash}:{chunk_index}:{total_chunks}:{chunk_hash}:{chunk_nonce}".encode()

        response = requests.post(
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks",
            files={
                "file": (
                    "chunk_1_compressed",
                    compressed_chunk_data,
                    "application/gzip",
                )
            },
            data={
                "nonce": chunk_nonce,
                "chunk_hash": chunk_hash,
                "chunk_index": str(chunk_index),
                "total_chunks": str(total_chunks),
                "compressed": "true",
                "classic_signature": data.sk_classic.sign(
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
        download_nonce = get_nonce(api_base_url)
        download_msg = f"DOWNLOAD-CHUNK:{data.pk_classic_hex}:{data.file_hash}:{chunk_hash}:{download_nonce}".encode()
        download_payload = {
            "chunk_hash": chunk_hash,
            "nonce": download_nonce,
            "classic_signature": data.sk_classic.sign(
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

        response = requests.post(
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks/{chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/gzip"
        assert response.content == compressed_chunk_data

        # Test 2: Download compressed chunk as decompressed
        download_nonce = get_nonce(api_base_url)
        download_msg = f"DOWNLOAD-CHUNK:{data.pk_classic_hex}:{data.file_hash}:{chunk_hash}:{download_nonce}".encode()
        download_payload = {
            "chunk_hash": chunk_hash,
            "nonce": download_nonce,
            "classic_signature": data.sk_classic.sign(
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
        response = requests.post(
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks/{chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        assert response.content == original_chunk_data
    finally:
        for sig in data.oqs_sigs_to_free:
            sig.free()


def test_download_chunk_unauthorized(api_base_url: str):
    """Tests that chunk download fails with invalid signatures."""
    data = setup_uploaded_file(api_base_url)
    try:
        pk_ml_dsa_hex = next(iter(data.all_pq_sks))
        sig_ml_dsa, _ = data.all_pq_sks[pk_ml_dsa_hex]
        chunk_hash = data.uploaded_chunks[0]["hash"]

        download_nonce = get_nonce(api_base_url)
        invalid_msg = b"wrong message for chunk download"
        invalid_sig = data.sk_classic.sign(invalid_msg, hashfunc=hashlib.sha256).hex()
        correct_download_msg = f"DOWNLOAD-CHUNK:{data.pk_classic_hex}:{data.file_hash}:{chunk_hash}:{download_nonce}".encode()
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

        response = requests.post(
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks/{chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    finally:
        for sig in data.oqs_sigs_to_free:
            sig.free()


def test_download_chunk_nonexistent(api_base_url: str):
    """Tests that downloading a non-existent chunk returns a 404 error."""
    data = setup_uploaded_file(api_base_url)
    try:
        pk_ml_dsa_hex = next(iter(data.all_pq_sks))
        sig_ml_dsa, _ = data.all_pq_sks[pk_ml_dsa_hex]

        fake_chunk_hash = "nonexistent-chunk-hash-12345"
        download_nonce = get_nonce(api_base_url)
        download_msg = f"DOWNLOAD-CHUNK:{data.pk_classic_hex}:{data.file_hash}:{fake_chunk_hash}:{download_nonce}".encode()
        download_payload = {
            "chunk_hash": fake_chunk_hash,
            "nonce": download_nonce,
            "classic_signature": data.sk_classic.sign(
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

        response = requests.post(
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks/{fake_chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 404
        assert "Chunk not found" in response.text
    finally:
        for sig in data.oqs_sigs_to_free:
            sig.free()


def test_concatenated_chunks_download_workflow(api_base_url: str):
    """Tests downloading the fully concatenated gzip file."""
    data = setup_uploaded_file(api_base_url)
    try:
        pk_ml_dsa_hex = next(iter(data.all_pq_sks))
        sig_ml_dsa, _ = data.all_pq_sks[pk_ml_dsa_hex]

        download_nonce = get_nonce(api_base_url)
        download_msg = f"DOWNLOAD-CHUNKS:{data.pk_classic_hex}:{data.file_hash}:{download_nonce}".encode()
        download_payload = {
            "nonce": download_nonce,
            "classic_signature": data.sk_classic.sign(
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

        response = requests.post(
            f"{api_base_url}/storage/{data.pk_classic_hex}/{data.file_hash}/chunks/download",
            json=download_payload,
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/gzip"
        assert "x-chunk-count" in response.headers
        assert int(response.headers["x-chunk-count"]) > 1

        with tempfile.NamedTemporaryFile(suffix=".gz", delete=True) as temp_file:
            temp_file.write(response.content)
            temp_file.flush()
            result = subprocess.run(
                ["gunzip", "-t", temp_file.name], capture_output=True
            )
            assert result.returncode == 0, (
                f"gunzip test failed: {result.stderr.decode()}"
            )
    finally:
        for sig in data.oqs_sigs_to_free:
            sig.free()
