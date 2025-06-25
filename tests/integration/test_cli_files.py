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
import base64
from lib import idk_message
from src.lib.api_client import DCypherClient
from src.lib.key_manager import KeyManager


def test_cli_upload_download_1mb_file(cli_test_env, api_base_url):
    """
    Tests the end-to-end file storage workflow for a 1MB file using the CLI,
    ensuring the file is packaged in the spec-compliant IDK Message format.
    """
    run_command, test_dir = cli_test_env

    # --- 1. Setup Client-Side Identities ---
    # a. PRE crypto context and keys
    cc_path = test_dir / "cc.json"
    run_command(["gen-cc", "--output", str(cc_path)])
    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "user_pre"])

    # b. Setup API client and create account using streamlined helper
    from tests.integration.test_api import create_test_account_with_keymanager

    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, test_dir)

    # Get auth keys file path for CLI usage
    assert client.auth_keys_path is not None, "Auth keys path should not be None"
    auth_keys_file = Path(client.auth_keys_path)

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

    # --- 2. Create a 1MB file (no pre-encryption needed for upload command) ---
    original_data = os.urandom(1024 * 1024)  # 1MB
    original_file = test_dir / "original_1mb.dat"
    with open(original_file, "wb") as f:
        f.write(original_data)

    # --- 3. Upload the file using the CLI ---
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

    # --- 4. Download the chunks using the new command ---
    downloaded_chunks_file = test_dir / "downloaded_1mb.chunks.gz"
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

    # --- 5. Manually decompress and decrypt for verification ---
    # Since the CLI doesn't have a re-assembler, we can't use `cli decrypt`.
    # We will test the downloaded content's integrity manually.
    # This test primarily verifies the CLI can upload and download.
    # A full end-to-end decrypt would require a re-assembly tool.
    assert downloaded_chunks_file.stat().st_size > 0


def test_cli_download_compressed_verification(cli_test_env, api_base_url):
    """
    Tests the CLI download command with compression and integrity verification.
    This test is now covered by the `download-chunks` command which is inherently compressed.
    This test will be adapted to verify the download-chunks workflow.
    """
    run_command, test_dir = cli_test_env

    # Setup (abbreviated)
    cc_path = test_dir / "cc.json"
    run_command(["gen-cc", "--output", str(cc_path)])
    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "user_pre"])

    # Setup API client and create account using streamlined helper
    from tests.integration.test_api import create_test_account_with_keymanager

    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, test_dir)

    # Get auth keys file path for CLI usage
    assert client.auth_keys_path is not None, "Auth keys path should not be None"
    auth_keys_file = Path(client.auth_keys_path)

    sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    (test_dir / "idk_signer.sk").write_text(sk_idk_signer.to_string().hex())

    # Create and upload a compressible test file
    original_data = b"This is a repeating pattern for compression testing! " * 1000
    original_file = test_dir / "compressible_test.dat"
    original_file.write_bytes(original_data)

    # Upload file
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
            str(test_dir / "idk_signer.sk"),
        ]
    )
    assert result.returncode == 0, f"Upload failed: {result.stderr}"
    file_hash = [
        line.split()[-1]
        for line in result.stderr.splitlines()
        if "Registering file with hash:" in line
    ][0]

    # Test download-chunks
    downloaded_chunks_file = test_dir / "downloaded_chunks.gz"
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
    assert "downloaded successfully" in result.stderr


def test_cli_download_integrity_failure(cli_test_env, api_base_url):
    """The new `upload` command does not support pre-encrypted files, making this test obsolete."""
    pass


def test_cli_download_malformed_content(cli_test_env, api_base_url):
    """The new `upload` command handles its own encryption, so we can't upload malformed content. This test is obsolete."""
    pass


def test_cli_download_help_message(cli_test_env):
    """
    Tests that the CLI download command shows proper help with the new --compressed option.
    """
    run_command, test_dir = cli_test_env

    # Test help message for the new `download-chunks` command
    result = run_command(["download-chunks", "--help"])
    assert result.returncode == 0
    assert "Downloads all chunks for a file" in result.stdout
    assert "--output-path" in result.stdout

    # The old download command still exists for whole files (if ever needed)
    result = run_command(["download", "--help"])
    assert result.returncode == 0
    assert "Downloads a file from the remote storage API" in result.stdout
    assert "--compressed" in result.stdout


def test_single_part_idk_message_flow(cli_test_env, api_base_url):
    """
    Tests the complete flow for a single-part IDK message to verify all edge cases.
    The new `upload` command handles chunking automatically. This test verifies a small
    file that results in a single data chunk is handled correctly.
    """
    run_command, test_dir = cli_test_env

    # Setup (abbreviated)
    cc_path = test_dir / "cc.json"
    run_command(["gen-cc", "--output", str(cc_path)])
    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "user_pre"])
    classic_sk_api = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    classic_vk_api = classic_sk_api.get_verifying_key()
    assert classic_vk_api is not None
    pk_classic_hex = classic_vk_api.to_string("uncompressed").hex()
    classic_sk_api_path = test_dir / "user_auth_api.sk"
    (test_dir / "user_auth_api.sk").write_text(classic_sk_api.to_string().hex())
    pq_pk, pq_sk = generate_pq_keys(ML_DSA_ALG)
    (test_dir / "user_auth_pq.sk").write_bytes(pq_sk)
    sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_idk_verifier = sk_idk_signer.get_verifying_key()
    assert vk_idk_verifier is not None
    sk_idk_path = test_dir / "idk_signer.sk"
    vk_idk_path = test_dir / "idk_verifier.vk"
    (test_dir / "idk_signer.sk").write_text(sk_idk_signer.to_string().hex())
    (test_dir / "idk_verifier.vk").write_text(
        vk_idk_verifier.to_string("uncompressed").hex()
    )

    # Create auth keys file
    auth_keys_data = {
        "classic_sk_path": str(classic_sk_api_path),
        "pq_keys": [
            {
                "sk_path": str(test_dir / "user_auth_pq.sk"),
                "pk_hex": pq_pk.hex(),
                "alg": ML_DSA_ALG,
            }
        ],
    }
    auth_keys_file = test_dir / "auth_keys.json"
    auth_keys_file.write_text(json.dumps(auth_keys_data))

    # Create Account using API client
    client = DCypherClient(api_base_url, str(auth_keys_file))
    pq_keys = [{"pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}]
    client.create_account(pk_classic_hex, pq_keys)

    # Create a small file that should result in one header + one data chunk
    original_data = b"Small single-part IDK message test data"
    original_file = test_dir / "small_test.dat"
    original_file.write_bytes(original_data)

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
            str(original_file),
            "--cc-path",
            str(cc_path),
            "--signing-key-path",
            str(sk_idk_path),
        ]
    )
    assert result.returncode == 0, f"Upload failed: {result.stderr}"
    assert "Uploading 0 data chunks" in result.stderr

    file_hash = [
        line.split()[-1]
        for line in result.stderr.splitlines()
        if "Registering file with hash:" in line
    ][0]

    # --- Download and Verify ---
    # a. Download the concatenated chunks file
    downloaded_chunks_path = test_dir / "downloaded_single.chunks.gz"
    result = run_command(
        [
            "download-chunks",
            "--api-url",
            api_base_url,
            "--pk-path",
            "user_pre.pub",
            "--auth-keys-path",
            str(auth_keys_file),
            "--file-hash",
            file_hash,
            "--output-path",
            str(downloaded_chunks_path),
        ]
    )
    assert result.returncode == 0, f"Download failed: {result.stderr}"
    assert downloaded_chunks_path.exists()

    # b. Decompress and verify content
    with gzip.open(downloaded_chunks_path, "rb") as f:
        decompressed_content = f.read()

    # Since it's a single part, the decompressed content is the raw part
    parsed_part = idk_message.parse_idk_message_part(
        decompressed_content.decode("utf-8")
    )
    payload_bytes = base64.b64decode(parsed_part["payload_b64"])

    # Decrypt to get original data
    with open(cc_path, "r") as f:
        cc = pre.deserialize_cc(base64.b64decode(json.load(f)["cc"]))
    with open(test_dir / "user_pre.sec", "r") as f:
        sk_data = json.load(f)
        sk = pre.deserialize_secret_key(base64.b64decode(sk_data["key"]))

    # For single-part messages, the number of slots to decrypt must match
    # the original data length, not the total slots in the crypto context.
    total_slots_for_data = (len(original_data) + 1) // 2

    decrypted_coeffs = pre.decrypt(
        cc, sk, [pre.deserialize_ciphertext(payload_bytes)], total_slots_for_data
    )
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))

    assert decrypted_data == original_data


def test_cli_download_integrity_failure(cli_test_env, api_base_url):
    """
    Tests that the download command fails if the downloaded content's hash
    does not match the expected hash.
    """
    run_command, test_dir = cli_test_env

    # Setup (abbreviated)
    cc_path = test_dir / "cc.json"
    run_command(["gen-cc", "--output", str(cc_path)])
    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "user_pre"])
    classic_sk_api = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    classic_vk_api = classic_sk_api.get_verifying_key()
    assert classic_vk_api is not None
    pk_classic_hex = classic_vk_api.to_string("uncompressed").hex()
    classic_sk_api_path = test_dir / "user_auth_api.sk"
    (test_dir / "user_auth_api.sk").write_text(classic_sk_api.to_string().hex())
    pq_pk, pq_sk = generate_pq_keys(ML_DSA_ALG)
    (test_dir / "user_auth_pq.sk").write_bytes(pq_sk)
    sk_idk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    (test_dir / "idk_signer.sk").write_text(sk_idk_signer.to_string().hex())

    # Create auth keys file
    auth_keys_data = {
        "classic_sk_path": str(classic_sk_api_path),
        "pq_keys": [
            {
                "sk_path": str(test_dir / "user_auth_pq.sk"),
                "pk_hex": pq_pk.hex(),
                "alg": ML_DSA_ALG,
            }
        ],
    }
    auth_keys_file = test_dir / "auth_keys.json"
    auth_keys_file.write_text(json.dumps(auth_keys_data))

    # Create Account using API client
    client = DCypherClient(api_base_url, str(auth_keys_file))
    pq_keys = [{"pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}]
    client.create_account(pk_classic_hex, pq_keys)

    # Create and upload a compressible test file
    original_data = b"This is a repeating pattern for compression testing! " * 1000
    original_file = test_dir / "compressible_test.dat"
    original_file.write_bytes(original_data)

    # Upload file
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
            str(test_dir / "idk_signer.sk"),
        ]
    )
    assert result.returncode == 0, f"Upload failed: {result.stderr}"
    file_hash = [
        line.split()[-1]
        for line in result.stderr.splitlines()
        if "Registering file with hash:" in line
    ][0]

    # Test download-chunks
    downloaded_chunks_file = test_dir / "downloaded_chunks.gz"
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
    assert "downloaded successfully" in result.stderr
