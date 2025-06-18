"""
This file tests the proxy re-encryption (PRE) library.
"""

import time
import random
from lib import pre


def test_pre_workflow():
    """
    A test case that walks through the PRE workflow using the pre library.
    """
    # Setup: Create a crypto context
    start_time = time.time()
    cc = pre.create_crypto_context()
    print(f"Parameter generation time: {(time.time() - start_time) * 1000:.2f} ms")

    print(f"p = {cc.GetPlaintextModulus()}")
    print(f"n = {cc.GetCyclotomicOrder() // 2}")
    ringsize = cc.GetRingDimension()
    print(f"Alice can encrypt {ringsize * 2} bytes of data")

    # Alice's Key Generation
    print("\nRunning Alice's key generation...")
    start_time = time.time()
    alice_keys = pre.generate_keys(cc)
    print(f"Key generation time: {(time.time() - start_time) * 1000:.2f} ms")

    # Bob's Key Generation
    print("\nRunning Bob's key generation...")
    start_time = time.time()
    bob_keys = pre.generate_keys(cc)
    print(f"Key generation time: {(time.time() - start_time) * 1000:.2f} ms")

    # Data to be encrypted
    nshort = ringsize
    original_data = [random.randint(0, 65535) for _ in range(nshort)]

    # Encryption by Alice
    print("\nEncrypting data with Alice's public key...")
    start_time = time.time()
    ciphertext_alice = pre.encrypt(cc, alice_keys.publicKey, original_data)
    print(f"Encryption time: {(time.time() - start_time) * 1000:.2f} ms")

    # Decryption by Alice (for verification)
    start_time = time.time()
    decrypted_by_alice = pre.decrypt(cc, alice_keys.secretKey, ciphertext_alice)
    print(f"Decryption time (by Alice): {(time.time() - start_time) * 1000:.2f} ms")

    # Generate Re-Encryption Key
    print("\nGenerating re-encryption key from Alice to Bob...")
    start_time = time.time()
    re_encryption_key = pre.generate_re_encryption_key(
        cc, alice_keys.secretKey, bob_keys.publicKey
    )
    print(
        f"Re-encryption key generation time: {(time.time() - start_time) * 1000:.2f} ms"
    )

    # Re-Encryption
    print("\nRe-encrypting ciphertext for Bob...")
    start_time = time.time()
    ciphertext_bob = pre.re_encrypt(cc, re_encryption_key, ciphertext_alice)
    print(f"Re-encryption time: {(time.time() - start_time) * 1000:.2f} ms")

    # Decryption by Bob
    start_time = time.time()
    decrypted_by_bob = pre.decrypt(cc, bob_keys.secretKey, ciphertext_bob)
    print(f"Decryption time (by Bob): {(time.time() - start_time) * 1000:.2f} ms")

    # Verification
    assert original_data == decrypted_by_alice, "Decryption by Alice failed"
    assert original_data == decrypted_by_bob, (
        "Decryption by Bob after re-encryption failed"
    )

    print("\nPRE workflow completed successfully!")


if __name__ == "__main__":
    test_pre_workflow()
