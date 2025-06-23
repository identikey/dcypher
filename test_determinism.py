import sys

sys.path.insert(0, "src")
import subprocess
import hashlib


def test_subprocess_determinism():
    algorithm = "ML-DSA-87"
    seed = hashlib.sha256(b"test seed").digest()

    # Test script that generates a key
    test_script = f"""
import sys
sys.path.insert(0, "src")
from lib.key_manager import KeyManager
import hashlib

seed = {seed!r}
pk, sk = KeyManager.generate_pq_keypair_from_seed("{algorithm}", seed)
print(pk[:10].hex())
"""

    # Run the same script twice in separate processes
    result1 = subprocess.run(
        ["uv", "run", "python", "-c", test_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=".",
    )
    result2 = subprocess.run(
        ["uv", "run", "python", "-c", test_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=".",
    )

    print(f"--- First run output ---\n{result1.stdout.strip()}")
    print(f"--- Second run output ---\n{result2.stdout.strip()}")

    # Extract last line for comparison
    pk1 = result1.stdout.strip().split("\n")[-1]
    pk2 = result2.stdout.strip().split("\n")[-1]

    print(f"First key: {pk1}")
    print(f"Second key: {pk2}")
    print(f"Same result: {pk1 == pk2}")


if __name__ == "__main__":
    test_subprocess_determinism()
