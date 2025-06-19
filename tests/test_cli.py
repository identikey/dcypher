import pytest
import subprocess
import os
from pathlib import Path
import sys
import json


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

        assert result.returncode == 0, "Command failed to execute."
        return result.stdout

    return run_command, tmp_path


def test_full_workflow(cli_test_env):
    run_command, test_dir = cli_test_env
    original_data = "1,2,3,4,5"
    original_data_list = "[1, 2, 3, 4, 5]"

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
            "--data",
            original_data,
            "--output",
            "ciphertext_alice.json",
        ]
    )
    assert (test_dir / "ciphertext_alice.json").exists()

    # 5. Decrypt with Alice's secret key
    output = run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "alice.sec",
            "--ciphertext-path",
            "ciphertext_alice.json",
        ]
    )
    assert output.strip() == original_data_list

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
    output = run_command(
        [
            "decrypt",
            "--cc-path",
            "cc.json",
            "--sk-path",
            "bob.sec",
            "--ciphertext-path",
            "reciphertext_bob.json",
        ]
    )
    assert output.strip() == original_data_list


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


if __name__ == "__main__":
    pytest.main(["-s", __file__])
