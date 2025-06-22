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


def test_encrypt_with_data_string(cli_test_env):
    """
    Tests the `encrypt` command using direct string input via the `--data` flag.
    This test now uses the spec-compliant IDK message format.
    """
    run_command, test_dir = cli_test_env
    original_data = "this is a test string"

    # 1. Generate Crypto Context and signing keys
    run_command(["gen-cc", "--output", "cc.json"])
    assert (test_dir / "cc.json").exists()
    sk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_verifier = sk_signer.get_verifying_key()
    assert vk_verifier is not None
    sk_path = test_dir / "signer.sk"
    vk_path = test_dir / "verifier.vk"
    with open(sk_path, "w") as f:
        f.write(sk_signer.to_string().hex())
    with open(vk_path, "w") as f:
        f.write(vk_verifier.to_string("uncompressed").hex())

    # 2. Generate Alice's keys
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "alice"])
    assert (test_dir / "alice.pub").exists()
    assert (test_dir / "alice.sec").exists()

    # 3. Encrypt data with Alice's public key using --data
    result = run_command(
        [
            "encrypt",
            "--cc-path",
            "cc.json",
            "--pk-path",
            "alice.pub",
            "--signing-key-path",
            str(sk_path),
            "--data",
            original_data,
            "--output",
            "ciphertext_alice.idk",
        ]
    )
    assert result.returncode == 0
    assert (test_dir / "ciphertext_alice.idk").exists()

    # 4. Decrypt with Alice's secret key
    decrypted_file_alice = test_dir / "decrypted_by_alice.txt"
    result = run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "alice.sec",
            "--verifying-key-path",
            str(vk_path),
            "--ciphertext-path",
            "ciphertext_alice.idk",
            "--output-file",
            str(decrypted_file_alice),
        ]
    )
    assert result.returncode == 0
    with open(decrypted_file_alice, "rb") as f:
        assert f.read() == original_data.encode("utf-8")


def test_encrypt_mutually_exclusive_options(cli_test_env):
    """
    Tests that the `encrypt` command fails if both `--data` and `--input-file`
    are provided, as they are mutually exclusive.
    """
    run_command, test_dir = cli_test_env
    input_file = test_dir / "input.txt"
    input_file.touch()  # Create a dummy file

    # Generate necessary keys and context
    run_command(["gen-cc", "--output", "cc.json"])
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "alice"])
    # Also need a signing key for the command to run
    sk_signer = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    sk_path = test_dir / "signer.sk"
    with open(sk_path, "w") as f:
        f.write(sk_signer.to_string().hex())

    # Attempt to run encrypt with both data and input file
    result = run_command(
        [
            "encrypt",
            "--cc-path",
            "cc.json",
            "--pk-path",
            "alice.pub",
            "--signing-key-path",
            str(sk_path),
            "--data",
            "some data",
            "--input-file",
            str(input_file),
            "--output",
            "ciphertext.json",
        ]
    )

    # Expect a non-zero return code indicating an error
    assert result.returncode != 0
    # Expect a usage error message from click
    assert "Error: Provide either --data or --input-file, not both." in result.stderr


if __name__ == "__main__":
    pytest.main(["-s", __file__])
