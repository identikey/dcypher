import pytest
import subprocess
import os
from pathlib import Path
import sys


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


if __name__ == "__main__":
    pytest.main(["-s", __file__])
