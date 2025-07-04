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
from src.lib.pq_auth import generate_pq_keys
from src.lib import pre
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

    # --- 1. Create Identity and Setup ---
    run_command(
        [
            "identity",
            "new",
            "--name",
            "TestUser",
            "--path",
            str(test_dir),
            "--api-url",
            api_base_url,
        ]
    )
    identity_file = test_dir / "TestUser.json"
    assert identity_file.exists()

    # Initialize PRE capabilities
    run_command(
        [
            "init-pre",
            "--identity-path",
            str(identity_file),
            "--api-url",
            api_base_url,
        ]
    )

    # Create account on server
    run_command(
        [
            "create-account",
            "--identity-path",
            str(identity_file),
            "--api-url",
            api_base_url,
        ]
    )

    # --- 2. Create a LARGE test file ---
    # Create a file large enough to test chunking (using a reasonable size)
    original_data = secrets.token_bytes(8192)  # 8KB should be enough to test chunking
    original_file = test_dir / "original_large.dat"
    with open(original_file, "wb") as f:
        f.write(original_data)

    # --- 3. Upload the file using the new CLI syntax ---
    result = run_command(
        [
            "upload",
            "--identity-path",
            str(identity_file),
            "--file-path",
            str(original_file),
            "--api-url",
            api_base_url,
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

    # --- 4. Download the chunks using the chunks download command ---
    # Note: download-chunks still uses the old syntax, we'll need to update that separately
    # For now, create a minimal auth keys file for download compatibility
    with open(identity_file, "r") as f:
        identity_data = json.load(f)

    classic_sk_hex = identity_data["auth_keys"]["classic"]["sk_hex"]
    classic_sk = ecdsa.SigningKey.from_string(
        bytes.fromhex(classic_sk_hex), curve=ecdsa.SECP256k1
    )
    classic_vk = classic_sk.get_verifying_key()
    assert classic_vk is not None
    pk_classic_hex = classic_vk.to_string("uncompressed").hex()

    # Create temp auth keys file for download command (download commands not yet updated)
    # Create temporary secret key files in auth_keys format
    classic_sk_file = test_dir / "temp_classic.sk"
    with open(classic_sk_file, "w") as f:
        f.write(classic_sk_hex)

    # Create PQ secret key files and build pq_keys list
    pq_keys_list = []
    for i, pq_key_data in enumerate(identity_data["auth_keys"]["pq"]):
        pq_sk_file = test_dir / f"temp_pq_{i}.sk"
        with open(pq_sk_file, "wb") as f:
            f.write(bytes.fromhex(pq_key_data["sk_hex"]))

        pq_keys_list.append(
            {
                "sk_path": str(pq_sk_file),
                "pk_hex": pq_key_data["pk_hex"],
                "alg": pq_key_data["alg"],
            }
        )

    temp_auth_file = test_dir / "temp_auth.json"
    temp_auth_data = {
        "classic_sk_path": str(classic_sk_file),
        "pq_keys": pq_keys_list,
    }
    with open(temp_auth_file, "w") as f:
        json.dump(temp_auth_data, f)

    downloaded_chunks_file = test_dir / "downloaded_large.chunks.gz"
    result = run_command(
        [
            "download-chunks",
            "--api-url",
            api_base_url,
            "--pk-path",
            pk_classic_hex,
            "--identity-path",
            str(identity_file),
            "--file-hash",
            file_hash,
            "--output-path",
            str(downloaded_chunks_file),
        ]
    )
    assert result.returncode == 0, f"Download failed: {result.stderr}"
    assert downloaded_chunks_file.exists()

    # --- 5. Reassemble and decrypt the downloaded file and verify ---
    # Decompress the downloaded Gzip file to get concatenated idk parts
    reassembled_idk_file = test_dir / "reassembled.idk"
    with (
        gzip.open(downloaded_chunks_file, "rb") as f_in,
        open(reassembled_idk_file, "wb") as f_out,
    ):
        content = f_in.read()
        if isinstance(content, str):
            content = content.encode("utf-8")
        f_out.write(content)

    # Get server crypto context for decryption
    cc_file = test_dir / "server_cc.dat"
    run_command(
        [
            "get-pre-context",
            "--output",
            str(cc_file),
            "--api-url",
            api_base_url,
        ]
    )

    # Convert to JSON format for CLI decrypt
    with open(cc_file, "rb") as f:
        cc_bytes = f.read()
    cc_b64 = base64.b64encode(cc_bytes).decode("ascii")
    cc_json_file = test_dir / "server_cc.json"
    with open(cc_json_file, "w") as f:
        json.dump({"cc": cc_b64}, f)

    # Get PRE secret key from identity
    pre_sk_hex = identity_data["auth_keys"]["pre"]["sk_hex"]
    pre_sk_bytes = bytes.fromhex(pre_sk_hex)
    pre_sk_b64 = base64.b64encode(pre_sk_bytes).decode("ascii")
    pre_sk_file = test_dir / "pre.sec"
    with open(pre_sk_file, "w") as f:
        json.dump({"key": pre_sk_b64}, f)

    # Create dummy verifying key (IDK messages handle verification internally)
    dummy_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    dummy_vk = dummy_sk.get_verifying_key()
    assert dummy_vk is not None
    dummy_vk_file = test_dir / "dummy.vk"
    with open(dummy_vk_file, "w") as f:
        f.write(dummy_vk.to_string("uncompressed").hex())

    # Decrypt the reassembled IDK file
    decrypted_file = test_dir / "decrypted_large.dat"
    result = run_command(
        [
            "decrypt",
            "--cc-path",
            str(cc_json_file),
            "--sk-path",
            str(pre_sk_file),
            "--verifying-key-path",
            str(dummy_vk_file),
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

    # --- 6. Test a small file (single chunk) ---
    original_data_small = b"This is a test with just one data chunk."
    original_file_small = test_dir / "original_single_chunk.dat"
    original_file_small.write_bytes(original_data_small)

    # Upload the small file using new syntax
    result = run_command(
        [
            "upload",
            "--identity-path",
            str(identity_file),
            "--file-path",
            str(original_file_small),
            "--api-url",
            api_base_url,
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
            "--identity-path",
            str(identity_file),
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
            str(cc_json_file),
            "--sk-path",
            str(pre_sk_file),
            "--verifying-key-path",
            str(dummy_vk_file),
            "--ciphertext-path",
            str(reassembled_small_idk),
            "--output-file",
            str(decrypted_file_small),
        ]
    )
    assert result.returncode == 0, f"Decrypt failed: {result.stderr}"
    assert decrypted_file_small.read_bytes() == original_data_small
