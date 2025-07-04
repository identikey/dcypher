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
from dcypher.config import ML_DSA_ALG
from dcypher.lib import pre
from dcypher.lib.idk_message import create_idk_message_parts, parse_idk_message_part

from tests.integration.test_api import (
    get_nonce,
    _create_test_idk_file_parts,
    create_test_account_with_keymanager,
)


def test_download_file_successful(api_base_url: str, tmp_path):
    """Tests the successful download of a whole file after chunked upload."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        # 1. Setup: Upload a file to be downloaded
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

        original_content = (
            b"This is a test file for downloading, with enough content for multiple chunks."
            * 250
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]

        # Register the file
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
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
        for i, chunk_content in enumerate(data_chunks, start=1):
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()
            chunk_nonce = get_nonce(api_base_url)
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()

            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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

        # 2. Perform the actual download test
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
        assert download_response.headers["content-type"] == "application/gzip"

    # OQS signatures are automatically freed when exiting the context


def test_download_file_unauthorized(api_base_url: str, tmp_path):
    """Tests that file download fails if the signatures are invalid."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        # 1. Setup: Upload a file to be downloaded
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

        original_content = b"This is a test file for unauthorized download." * 250
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]

        # Register the file
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "unauthorized_download_test.txt",
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
        for i, chunk_content in enumerate(data_chunks, start=1):
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()
            chunk_nonce = get_nonce(api_base_url)
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()
            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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

        # 2. Perform the actual download test with an invalid signature
        download_nonce = get_nonce(api_base_url)
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

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/download",
            json=download_payload,
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    # OQS signatures are automatically freed when exiting the context


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


def test_download_chunk_compressed(api_base_url: str, tmp_path):
    """Tests downloading individual chunks with compression handling."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        # 1. Setup: Upload a file to be downloaded
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

        original_content = (
            b"This is a test file for compressed chunk download, it needs to be large enough to be split into multiple parts."
            * 1000
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]

        # Register the file
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "compressed_chunk_test.txt",
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

        # Upload subsequent chunks (uncompressed)
        uploaded_chunks_info = []
        for i, chunk_content in enumerate(data_chunks, start=1):
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()
            chunk_nonce = get_nonce(api_base_url)
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()

            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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
            uploaded_chunks_info.append(
                {"hash": chunk_hash, "original_data": chunk_bytes}
            )

        # 2. Re-upload one chunk with compression to test this feature
        chunk_to_compress = uploaded_chunks_info[0]
        original_chunk_data = chunk_to_compress["original_data"]
        compressed_chunk_data = gzip.compress(original_chunk_data, compresslevel=9)
        chunk_hash = chunk_to_compress["hash"]
        chunk_index = 1

        chunk_nonce = get_nonce(api_base_url)
        chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{chunk_index}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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
                "total_chunks": str(len(idk_parts)),
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

        # 3. Test Download compressed chunk as compressed
        download_nonce = get_nonce(api_base_url)
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

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/gzip"
        assert response.content == compressed_chunk_data

        # 4. Test Download compressed chunk as decompressed
        download_nonce = get_nonce(api_base_url)
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
        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        assert response.content == original_chunk_data
    # OQS signatures are automatically freed when exiting the context


def test_download_chunk_unauthorized(api_base_url: str, tmp_path):
    """Tests that chunk download fails with invalid signatures."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        # 1. Setup: Upload a file to be downloaded
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

        original_content = (
            b"This is a test file for unauthorized chunk download, needs to be big."
            * 1000
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]
        assert data_chunks, "Test requires at least one data chunk"

        # Register the file
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "unauthorized_chunk_test.txt",
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
            chunk_nonce = get_nonce(api_base_url)
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()
            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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
            uploaded_chunks_info.append(
                {"hash": chunk_hash, "original_data": chunk_bytes}
            )

        # 2. Perform the actual download test with an invalid signature
        chunk_hash = uploaded_chunks_info[0]["hash"]
        download_nonce = get_nonce(api_base_url)
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

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/{chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text
    # OQS signatures are automatically freed when exiting the context


def test_download_chunk_nonexistent(api_base_url: str, tmp_path):
    """Tests that downloading a non-existent chunk returns a 404 error."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        # 1. Setup: Upload a file to be downloaded
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

        original_content = (
            b"This is a test file for unauthorized chunk download, needs to be big."
            * 1000
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]
        assert data_chunks, "Test requires at least one data chunk"

        # Register the file
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "unauthorized_chunk_test.txt",
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
            chunk_nonce = get_nonce(api_base_url)
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()
            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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
            uploaded_chunks_info.append(
                {"hash": chunk_hash, "original_data": chunk_bytes}
            )

        # 2. Perform the actual download test with an invalid signature
        chunk_hash = uploaded_chunks_info[0]["hash"]
        download_nonce = get_nonce(api_base_url)
        fake_chunk_hash = "nonexistent-chunk-hash-12345"
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

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/{fake_chunk_hash}/download",
            json=download_payload,
        )
        assert response.status_code == 404
        assert "Chunk not found" in response.text
    # OQS signatures are automatically freed when exiting the context


def test_concatenated_chunks_download_workflow(api_base_url: str, tmp_path):
    """Tests downloading the fully concatenated gzip file."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        # 1. Setup: Upload a file to be downloaded
        sk_classic = keys["classic_sk"]
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]

        original_content = (
            b"This is a test file for concatenated chunk download workflow." * 1000
        )
        idk_parts, file_hash = _create_test_idk_file_parts(original_content)
        part_one = idk_parts[0]
        data_chunks = idk_parts[1:]
        assert data_chunks, "Test requires at least one data chunk"

        # Register the file
        register_nonce = get_nonce(api_base_url)
        register_msg = (
            f"REGISTER:{pk_classic_hex}:{file_hash}:{register_nonce}".encode()
        )
        register_response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/register",
            files={
                "idk_part_one": ("test.idk.part1", part_one, "application/octet-stream")
            },
            data={
                "nonce": register_nonce,
                "filename": "concatenated_download_test.txt",
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
        for i, chunk_content in enumerate(data_chunks, start=1):
            chunk_bytes = chunk_content.encode("utf-8")
            chunk_hash = hashlib.blake2b(chunk_bytes).hexdigest()
            chunk_nonce = get_nonce(api_base_url)
            chunk_msg = f"UPLOAD-CHUNK:{pk_classic_hex}:{file_hash}:{i}:{len(idk_parts)}:{chunk_hash}:{chunk_nonce}".encode()
            chunk_response = requests.post(
                f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks",
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

        # 2. Perform the actual download test
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

        response = requests.post(
            f"{api_base_url}/storage/{pk_classic_hex}/{file_hash}/chunks/download",
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
    # OQS signatures are automatically freed when exiting the context
