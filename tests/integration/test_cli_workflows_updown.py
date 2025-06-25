import pytest
import subprocess
import os
from pathlib import Path
import sys
import json
import secrets
import ecdsa
import oqs
import requests
import threading
import uvicorn
import time
from main import (
    app,
)
from config import ML_DSA_ALG
from app_state import state
from lib.pq_auth import generate_pq_keys
from lib import pre
from fastapi.testclient import TestClient
import click
import hashlib
import socket
import gzip
from src.lib.api_client import DCypherClient
import base64


def test_cli_upload_download_workflow(cli_test_env, api_base_url):
    """
    Tests the end-to-end file storage workflow using the CLI against a live API.

    This integration test covers:
    1.  Client-side identity generation (PRE, authentication, and message signing keys).
    2.  Account creation on the remote server.
    3.  Encryption of a file into the spec-compliant IDK message format.
    4.  Uploading the encrypted file using the `upload` command.
    5.  Downloading the file using the `download` command.
    6.  Verifying and decrypting the downloaded IDK message.

    It ensures that the CLI can correctly interact with the API for storing
    and retrieving large, encrypted files that adhere to the message spec.
    """
    run_command, test_dir = cli_test_env

    # --- 1. Setup Client-Side Identities ---
    # a. PRE crypto context and keys
    cc_path = test_dir / "cc.json"
    run_command(["gen-cc", "--output", str(cc_path)])

    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))
    slot_count = pre.get_slot_count(cc)

    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "user_pre"])

    # b. Authentication keys for API
    classic_sk_api = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    classic_vk_api = classic_sk_api.get_verifying_key()
    assert classic_vk_api is not None
    pk_classic_hex = classic_vk_api.to_string("uncompressed").hex()
    classic_sk_api_path = test_dir / "user_auth_api.sk"
    with open(classic_sk_api_path, "w") as f:
        f.write(classic_sk_api.to_string().hex())

    pq_pk, pq_sk = generate_pq_keys(ML_DSA_ALG)
    pq_sk_path = test_dir / "user_auth_pq.sk"
    with open(pq_sk_path, "wb") as f:
        f.write(pq_sk)

    # c. Signing keys for IDK Message Format
    sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_idk_verifier = sk_idk_signer.get_verifying_key()
    assert vk_idk_verifier is not None
    sk_idk_path = test_dir / "idk_signer.sk"
    vk_idk_path = test_dir / "idk_verifier.vk"
    with open(sk_idk_path, "w") as f:
        f.write(sk_idk_signer.to_string().hex())
    with open(vk_idk_path, "w") as f:
        f.write(vk_idk_verifier.to_string("uncompressed").hex())

    # --- 2. Create Account using API client ---
    auth_keys_data = {
        "classic_sk_path": str(classic_sk_api_path),
        "pq_keys": [
            {"sk_path": str(pq_sk_path), "pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}
        ],
    }
    auth_keys_file = test_dir / "auth_keys.json"
    with open(auth_keys_file, "w") as f:
        json.dump(auth_keys_data, f)

    client = DCypherClient(api_base_url, str(auth_keys_file))
    pq_keys = [{"pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}]
    client.create_account(pk_classic_hex, pq_keys)

    # --- 4. Encrypt a LARGE file ---
    # Use a size guaranteed to be > slot_count to test chunking
    original_data = secrets.token_bytes(slot_count + 10)
    original_file = test_dir / "original_large.dat"
    with open(original_file, "wb") as f:
        f.write(original_data)

    encrypted_file = test_dir / "encrypted_large.idk"
    result = run_command(
        [
            "encrypt",
            "--cc-path",
            str(cc_path),
            "--pk-path",
            "user_pre.pub",
            "--signing-key-path",
            str(sk_idk_path),
            "--input-file",
            str(original_file),
            "--output",
            str(encrypted_file),
        ]
    )
    assert result.returncode == 0

    # --- 5. Upload the file using the CLI ---
    result = run_command(
        [
            "upload",
            "--api-url",
            api_base_url,
            "--pk-path",
            "user_pre.pub",
            "--auth-keys-path",
            str(auth_keys_file),
            "--file-path",
            str(original_file),
            "--cc-path",
            str(cc_path),
            "--signing-key-path",
            str(sk_idk_path),
        ]
    )
    assert result.returncode == 0, f"Upload failed: {result.stderr}"

    # Extract file hash from the registration message
    file_hash = ""
    for line in result.stderr.splitlines():
        if "Registering file with hash:" in line:
            file_hash = line.split()[-1]
            break
    assert file_hash, "Could not find file hash in upload output."

    # --- 6. Download the chunks using the chunks download command ---
    downloaded_chunks_file = test_dir / "downloaded_large.chunks.gz"
    result = run_command(
        [
            "download-chunks",
            "--api-url",
            api_base_url,
            "--pk-path",
            pk_classic_hex,
            "--auth-keys-path",
            str(auth_keys_file),
            "--file-hash",
            file_hash,
            "--output-path",
            str(downloaded_chunks_file),
        ]
    )
    assert result.returncode == 0, f"Download failed: {result.stderr}"
    assert downloaded_chunks_file.exists()

    # --- 7. Reassemble and decrypt the downloaded file and verify ---
    # a. Decompress the downloaded Gzip file to get concatenated idk parts
    reassembled_idk_file = test_dir / "reassembled.idk"
    with (
        gzip.open(downloaded_chunks_file, "rb") as f_in,
        open(reassembled_idk_file, "wb") as f_out,
    ):
        content = f_in.read()
        if isinstance(content, str):
            content = content.encode("utf-8")
        f_out.write(content)

    # c. Decrypt the reassembled IDK file
    decrypted_file = test_dir / "decrypted_large.dat"
    result = run_command(
        [
            "decrypt",
            "--cc-path",
            str(cc_path),
            "--sk-path",
            "user_pre.sec",
            "--verifying-key-path",
            str(vk_idk_path),
            "--ciphertext-path",
            str(reassembled_idk_file),
            "--output-file",
            str(decrypted_file),
        ]
    )
    assert result.returncode == 0, f"Decrypt failed: {result.stderr}"
    with open(decrypted_file, "rb") as f:
        assert f.read() == original_data

    click.echo(
        "CLI upload/download/decrypt workflow successful with large file!", err=True
    )

    # Test a file small enough to not require chunking beyond the header
    original_data_small = b"This is a test with just one data chunk."
    original_file_small = test_dir / "original_single_chunk.dat"
    original_file_small.write_bytes(original_data_small)

    # Upload the small file
    result = run_command(
        [
            "upload",
            "--api-url",
            api_base_url,
            "--pk-path",
            "user_pre.pub",
            "--auth-keys-path",
            str(auth_keys_file),
            "--file-path",
            str(original_file_small),
            "--cc-path",
            str(cc_path),
            "--signing-key-path",
            str(sk_idk_path),
        ]
    )
    assert result.returncode == 0, f"Upload failed: {result.stderr}"
    assert "Uploading 0 data chunks..." in result.stderr

    file_hash_small = [
        line.split()[-1]
        for line in result.stderr.splitlines()
        if "Registering file with hash:" in line
    ][0]

    # Download the chunks (even if there's only one part in the gzip)
    downloaded_file_small = test_dir / "downloaded_single_chunk.chunks.gz"
    result = run_command(
        [
            "download-chunks",
            "--api-url",
            api_base_url,
            "--pk-path",
            pk_classic_hex,
            "--auth-keys-path",
            str(auth_keys_file),
            "--file-hash",
            file_hash_small,
            "--output-path",
            str(downloaded_file_small),
        ]
    )
    assert result.returncode == 0, (
        f"Download failed for small file with hash {file_hash_small}:\n{result.stderr}"
    )
    assert downloaded_file_small.exists()

    # Decompress, reassemble, and verify
    reassembled_small_idk = test_dir / "reassembled_small.idk"
    with (
        gzip.open(downloaded_file_small, "rb") as f_in,
        open(reassembled_small_idk, "wb") as f_out,
    ):
        content = f_in.read()
        if isinstance(content, str):
            content = content.encode("utf-8")
        f_out.write(content)

    decrypted_file_small = test_dir / "decrypted_single_chunk.dat"
    result = run_command(
        [
            "decrypt",
            "--cc-path",
            str(cc_path),
            "--sk-path",
            "user_pre.sec",
            "--verifying-key-path",
            str(vk_idk_path),
            "--ciphertext-path",
            str(reassembled_small_idk),
            "--output-file",
            str(decrypted_file_small),
        ]
    )
    assert result.returncode == 0, f"Decrypt failed: {result.stderr}"
    assert decrypted_file_small.read_bytes() == original_data_small
