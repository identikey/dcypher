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
from src.main import (
    app,
    ML_DSA_ALG,
    accounts,
    used_nonces,
    graveyard,
    block_store,
    chunk_store,
)
from src.lib.pq_auth import generate_pq_keys
from src.lib import pre
from fastapi.testclient import TestClient
import click
import hashlib


API_BASE_URL = "http://127.0.0.1:8000"


@pytest.fixture(scope="session", autouse=True)
def live_api_server():
    """
    Starts the FastAPI app in a background thread for the test session,
    ensuring subprocesses can make real HTTP calls to it.
    """
    config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="warning")
    server = uvicorn.Server(config)
    ready_event = threading.Event()

    def run_server():
        original_startup = server.startup

        async def new_startup(sockets=None):
            await original_startup(sockets=sockets)
            ready_event.set()

        server.startup = new_startup
        server.run()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    if not ready_event.wait(timeout=10):
        raise RuntimeError("Uvicorn server failed to start in time.")

    yield


@pytest.fixture(autouse=True)
def cleanup_stores():
    """Cleans up the in-memory stores and directories before each test."""
    accounts.clear()
    used_nonces.clear()
    graveyard.clear()
    block_store.clear()
    chunk_store.clear()
    if os.path.exists("block_store"):
        for filename in os.listdir("block_store"):
            os.remove(os.path.join("block_store", filename))
    if os.path.exists("chunk_store"):
        for filename in os.listdir("chunk_store"):
            os.remove(os.path.join("chunk_store", filename))


@pytest.fixture(scope="module")
def api_client():
    """Provides a client for the FastAPI application."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def cli_test_env(tmp_path, request):
    """
    Sets up a test environment with a temporary directory and a helper for running CLI commands.
    """
    cli_path = Path(os.getcwd()) / "src" / "cli.py"

    def run_command(cmd):
        full_cmd = ["python3", str(cli_path)] + cmd
        result = subprocess.run(
            full_cmd, cwd=tmp_path, capture_output=True, text=True, check=False
        )

        if request.config.getoption("capture") == "no":
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)

        if result.returncode != 0:
            print("Error running command:", " ".join(full_cmd))
            print("Stdout:", result.stdout)
            print("Stderr:", result.stderr)

        # Allow commands to fail, as we need to test failure cases
        # assert result.returncode == 0, f"Command failed: {' '.join(full_cmd)}\n{result.stderr}"
        return result

    return run_command, tmp_path


def test_full_workflow(cli_test_env):
    run_command, test_dir = cli_test_env
    original_data = b"this is a test"
    input_file = test_dir / "input.txt"
    with open(input_file, "wb") as f:
        f.write(original_data)

    # 1. Generate Crypto Context
    run_command(["gen-cc", "--output", "cc.json"])
    assert (test_dir / "cc.json").exists()

    # 2. Generate Alice's keys
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "alice"])
    assert (test_dir / "alice.pub").exists()
    assert (test_dir / "alice.sec").exists()

    # 3. Generate Bob's keys
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "bob"])
    assert (test_dir / "bob.pub").exists()
    assert (test_dir / "bob.sec").exists()

    # 4. Encrypt data with Alice's public key
    run_command(
        [
            "encrypt",
            "--cc-path",
            "cc.json",
            "--pk-path",
            "alice.pub",
            "--input-file",
            str(input_file),
            "--output",
            "ciphertext_alice.json",
        ]
    )
    assert (test_dir / "ciphertext_alice.json").exists()

    # 5. Decrypt with Alice's secret key
    decrypted_file_alice = test_dir / "decrypted_by_alice.txt"
    run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "alice.sec",
            "--ciphertext-path",
            "ciphertext_alice.json",
            "--output-file",
            str(decrypted_file_alice),
        ]
    )
    with open(decrypted_file_alice, "rb") as f:
        assert f.read() == original_data

    # 6. Generate re-encryption key from Alice to Bob
    run_command(
        [
            "gen-rekey",
            "--cc-path",
            "cc.json",
            "--sk-path-from",
            "alice.sec",
            "--pk-path-to",
            "bob.pub",
            "--output",
            "rekey_alice_to_bob.json",
        ]
    )
    assert (test_dir / "rekey_alice_to_bob.json").exists()

    # 7. Re-encrypt ciphertext for Bob
    run_command(
        [
            "re-encrypt",
            "--cc-path",
            "cc.json",
            "--rekey-path",
            "rekey_alice_to_bob.json",
            "--ciphertext-path",
            "ciphertext_alice.json",
            "--output",
            "reciphertext_bob.json",
        ]
    )
    assert (test_dir / "reciphertext_bob.json").exists()

    # 8. Decrypt with Bob's secret key
    decrypted_file_bob = test_dir / "decrypted_by_bob.txt"
    run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "bob.sec",
            "--ciphertext-path",
            "reciphertext_bob.json",
            "--output-file",
            str(decrypted_file_bob),
        ]
    )
    with open(decrypted_file_bob, "rb") as f:
        assert f.read() == original_data


def test_full_workflow_with_string(cli_test_env):
    run_command, test_dir = cli_test_env
    original_data = b"This is a secret message."
    input_file = test_dir / "input.txt"
    with open(input_file, "wb") as f:
        f.write(original_data)

    # 1. Generate Crypto Context
    run_command(["gen-cc", "--output", "cc.json"])
    assert (test_dir / "cc.json").exists()

    # 2. Generate Alice's keys
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "alice"])
    assert (test_dir / "alice.pub").exists()
    assert (test_dir / "alice.sec").exists()

    # 3. Generate Bob's keys
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "bob"])
    assert (test_dir / "bob.pub").exists()
    assert (test_dir / "bob.sec").exists()

    # 4. Encrypt data with Alice's public key
    run_command(
        [
            "encrypt",
            "--cc-path",
            "cc.json",
            "--pk-path",
            "alice.pub",
            "--input-file",
            str(input_file),
            "--output",
            "ciphertext_alice.json",
        ]
    )
    assert (test_dir / "ciphertext_alice.json").exists()

    # 5. Decrypt with Alice's secret key
    decrypted_file_alice = test_dir / "decrypted_by_alice.txt"
    run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "alice.sec",
            "--ciphertext-path",
            "ciphertext_alice.json",
            "--output-file",
            str(decrypted_file_alice),
        ]
    )
    with open(decrypted_file_alice, "rb") as f:
        assert f.read() == original_data

    # 6. Generate re-encryption key from Alice to Bob
    run_command(
        [
            "gen-rekey",
            "--cc-path",
            "cc.json",
            "--sk-path-from",
            "alice.sec",
            "--pk-path-to",
            "bob.pub",
            "--output",
            "rekey_alice_to_bob.json",
        ]
    )
    assert (test_dir / "rekey_alice_to_bob.json").exists()

    # 7. Re-encrypt ciphertext for Bob
    run_command(
        [
            "re-encrypt",
            "--cc-path",
            "cc.json",
            "--rekey-path",
            "rekey_alice_to_bob.json",
            "--ciphertext-path",
            "ciphertext_alice.json",
            "--output",
            "reciphertext_bob.json",
        ]
    )
    assert (test_dir / "reciphertext_bob.json").exists()

    # 8. Decrypt with Bob's secret key
    decrypted_file_bob = test_dir / "decrypted_by_bob.txt"
    run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "bob.sec",
            "--ciphertext-path",
            "reciphertext_bob.json",
            "--output-file",
            str(decrypted_file_bob),
        ]
    )
    with open(decrypted_file_bob, "rb") as f:
        assert f.read() == original_data


def test_full_workflow_with_random_bytes(cli_test_env):
    run_command, test_dir = cli_test_env
    original_data = os.urandom(128)  # 128 random bytes
    input_file = test_dir / "input.bin"
    with open(input_file, "wb") as f:
        f.write(original_data)

    # 1. Generate Crypto Context
    run_command(["gen-cc", "--output", "cc.json"])
    assert (test_dir / "cc.json").exists()

    # 2. Generate Alice's keys
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "alice"])
    assert (test_dir / "alice.pub").exists()
    assert (test_dir / "alice.sec").exists()

    # 3. Generate Bob's keys
    run_command(["gen-keys", "--cc-path", "cc.json", "--output-prefix", "bob"])
    assert (test_dir / "bob.pub").exists()
    assert (test_dir / "bob.sec").exists()

    # 4. Encrypt data with Alice's public key
    run_command(
        [
            "encrypt",
            "--cc-path",
            "cc.json",
            "--pk-path",
            "alice.pub",
            "--input-file",
            str(input_file),
            "--output",
            "ciphertext_alice.json",
        ]
    )
    assert (test_dir / "ciphertext_alice.json").exists()

    # 5. Decrypt with Alice's secret key
    decrypted_file_alice = test_dir / "decrypted_by_alice.bin"
    run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "alice.sec",
            "--ciphertext-path",
            "ciphertext_alice.json",
            "--output-file",
            str(decrypted_file_alice),
        ]
    )
    with open(decrypted_file_alice, "rb") as f:
        assert f.read() == original_data

    # 6. Generate re-encryption key from Alice to Bob
    run_command(
        [
            "gen-rekey",
            "--cc-path",
            "cc.json",
            "--sk-path-from",
            "alice.sec",
            "--pk-path-to",
            "bob.pub",
            "--output",
            "rekey_alice_to_bob.json",
        ]
    )
    assert (test_dir / "rekey_alice_to_bob.json").exists()

    # 7. Re-encrypt ciphertext for Bob
    run_command(
        [
            "re-encrypt",
            "--cc-path",
            "cc.json",
            "--rekey-path",
            "rekey_alice_to_bob.json",
            "--ciphertext-path",
            "ciphertext_alice.json",
            "--output",
            "reciphertext_bob.json",
        ]
    )
    assert (test_dir / "reciphertext_bob.json").exists()

    # 8. Decrypt with Bob's secret key
    decrypted_file_bob = test_dir / "decrypted_by_bob.bin"
    run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "bob.sec",
            "--ciphertext-path",
            "reciphertext_bob.json",
            "--output-file",
            str(decrypted_file_bob),
        ]
    )
    with open(decrypted_file_bob, "rb") as f:
        assert f.read() == original_data


def test_large_file_workflow(cli_test_env):
    run_command, test_dir = cli_test_env

    # First, generate a crypto context to find out the slot count
    cc_path = test_dir / "cc.json"
    run_command(["gen-cc", "--output", str(cc_path)])
    assert cc_path.exists()

    # We need to load the cc to get the slot count, so we'll do it manually here
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    from src.lib import pre

    cc = pre.deserialize_cc(cc_data["cc"])
    slot_count = pre.get_slot_count(cc)

    # Create a file larger than the slot count
    # Use a mix of random and zero bytes to ensure robustness
    original_data = os.urandom(slot_count * 2) + b"\x00" * 10 + os.urandom(5)
    input_file = test_dir / "large_input.bin"
    with open(input_file, "wb") as f:
        f.write(original_data)

    # Now, run the full workflow with this large file
    # 1. Generate keys (cc already generated)
    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "alice"])
    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "bob"])

    # 2. Encrypt
    ciphertext_path = test_dir / "ciphertext.json"
    run_command(
        [
            "encrypt",
            "--cc-path",
            str(cc_path),
            "--pk-path",
            "alice.pub",
            "--input-file",
            str(input_file),
            "--output",
            str(ciphertext_path),
        ]
    )
    assert ciphertext_path.exists()

    # 3. Decrypt with Alice's key
    decrypted_file_alice = test_dir / "decrypted_by_alice.bin"
    run_command(
        [
            "decrypt",
            "--cc-path",
            str(cc_path),
            "--sk-path",
            "alice.sec",
            "--ciphertext-path",
            str(ciphertext_path),
            "--output-file",
            str(decrypted_file_alice),
        ]
    )
    with open(decrypted_file_alice, "rb") as f:
        assert f.read() == original_data

    # 4. Generate re-encryption key and re-encrypt
    rekey_path = test_dir / "rekey.json"
    run_command(
        [
            "gen-rekey",
            "--cc-path",
            str(cc_path),
            "--sk-path-from",
            "alice.sec",
            "--pk-path-to",
            "bob.pub",
            "--output",
            str(rekey_path),
        ]
    )
    reciphertext_path = test_dir / "reciphertext.json"
    run_command(
        [
            "re-encrypt",
            "--cc-path",
            str(cc_path),
            "--rekey-path",
            str(rekey_path),
            "--ciphertext-path",
            str(ciphertext_path),
            "--output",
            str(reciphertext_path),
        ]
    )

    # 5. Decrypt with Bob's key
    decrypted_file_bob = test_dir / "decrypted_by_bob.bin"
    run_command(
        [
            "decrypt",
            "--cc-path",
            str(cc_path),
            "--sk-path",
            "bob.sec",
            "--ciphertext-path",
            str(reciphertext_path),
            "--output-file",
            str(decrypted_file_bob),
        ]
    )
    with open(decrypted_file_bob, "rb") as f:
        assert f.read() == original_data


def test_cli_upload_download_workflow(cli_test_env):
    """
    Tests the full upload/download workflow through the CLI, including
    with a file larger than the PRE slot size.
    This requires a running API instance.
    """
    run_command, test_dir = cli_test_env

    # --- 1. Setup Client-Side Identities ---
    # a. PRE crypto context and keys
    cc_path = test_dir / "cc.json"
    run_command(["gen-cc", "--output", str(cc_path)])
    assert cc_path.exists()

    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(cc_data["cc"])
    slot_count = pre.get_slot_count(cc)

    run_command(["gen-keys", "--cc-path", str(cc_path), "--output-prefix", "user_pre"])
    assert (test_dir / "user_pre.pub").exists()
    assert (test_dir / "user_pre.sec").exists()

    # b. Authentication keys for API
    classic_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    classic_vk = classic_sk.verifying_key
    pk_classic_hex = classic_vk.to_string("uncompressed").hex()
    classic_sk_path = test_dir / "user_auth.sk"
    with open(classic_sk_path, "w") as f:
        f.write(classic_sk.to_string().hex())

    pq_pk, pq_sk = generate_pq_keys(ML_DSA_ALG)
    pq_sk_path = test_dir / "user_auth_pq.sk"
    with open(pq_sk_path, "wb") as f:
        f.write(pq_sk)

    # --- 2. Create Account on the API (using requests) ---
    nonce_resp = requests.get(f"{API_BASE_URL}/nonce")
    assert nonce_resp.status_code == 200
    nonce = nonce_resp.json()["nonce"]

    message = f"{pk_classic_hex}:{pq_pk.hex()}:{nonce}".encode("utf-8")
    with oqs.Signature(ML_DSA_ALG, pq_sk) as sig_ml_dsa:
        create_payload = {
            "public_key": pk_classic_hex,
            "signature": classic_sk.sign(message, hashfunc=hashlib.sha256).hex(),
            "ml_dsa_signature": {
                "public_key": pq_pk.hex(),
                "signature": sig_ml_dsa.sign(message).hex(),
                "alg": ML_DSA_ALG,
            },
            "nonce": nonce,
        }
    response = requests.post(f"{API_BASE_URL}/accounts", json=create_payload)
    assert response.status_code == 200, response.text

    # --- 3. Prepare auth keys file for CLI ---
    auth_keys_data = {
        "classic_sk_path": str(classic_sk_path),
        "pq_keys": [
            {"sk_path": str(pq_sk_path), "pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}
        ],
    }
    auth_keys_file = test_dir / "auth_keys.json"
    with open(auth_keys_file, "w") as f:
        json.dump(auth_keys_data, f)

    # --- 4. Encrypt a LARGE file ---
    # Use a size guaranteed to be > slot_count to test chunking
    original_data = secrets.token_bytes(slot_count + 10)
    original_file = test_dir / "original_large.dat"
    with open(original_file, "wb") as f:
        f.write(original_data)

    encrypted_file = test_dir / "encrypted_large.json"
    result = run_command(
        [
            "encrypt",
            "--cc-path",
            str(cc_path),
            "--pk-path",
            "user_pre.pub",
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
            "--pk-path",
            pk_classic_hex,
            "--auth-keys-path",
            str(auth_keys_file),
            "--file-path",
            str(encrypted_file),
        ]
    )
    assert result.returncode == 0, f"Upload failed: {result.stderr}"
    upload_response = json.loads(result.stdout)
    file_hash = upload_response["file_hash"]

    # --- 6. Download the file using the CLI ---
    downloaded_file = test_dir / "downloaded_large.json"
    result = run_command(
        [
            "download",
            "--pk-path",
            pk_classic_hex,
            "--auth-keys-path",
            str(auth_keys_file),
            "--file-hash",
            file_hash,
            "--output-path",
            str(downloaded_file),
        ]
    )
    assert result.returncode == 0, f"Download failed: {result.stderr}"
    assert downloaded_file.exists()

    # --- 7. Decrypt the downloaded file and verify ---
    decrypted_file = test_dir / "decrypted_large.dat"
    result = run_command(
        [
            "decrypt",
            "--cc-path",
            str(cc_path),
            "--sk-path",
            "user_pre.sec",
            "--ciphertext-path",
            str(downloaded_file),
            "--output-file",
            str(decrypted_file),
        ]
    )
    assert result.returncode == 0
    with open(decrypted_file, "rb") as f:
        assert f.read() == original_data

    click.echo(
        "CLI upload/download/decrypt workflow successful with large file!", err=True
    )


if __name__ == "__main__":
    pytest.main(["-s", __file__])
