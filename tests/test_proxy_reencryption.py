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

    print("\n--- Testing Serialization/Deserialization ---")

    # 1. Serialize all objects
    start_time = time.time()
    ser_cc = pre.serialize(cc)
    ser_alice_pk = pre.serialize(alice_keys.publicKey)
    ser_alice_sk = pre.serialize(alice_keys.secretKey)
    ser_bob_pk = pre.serialize(bob_keys.publicKey)
    ser_bob_sk = pre.serialize(bob_keys.secretKey)
    ser_ciphertext_alice = pre.serialize(ciphertext_alice)
    ser_re_key = pre.serialize(re_encryption_key)
    print(f"Serialization time: {(time.time() - start_time) * 1000:.2f} ms")

    # 2. Deserialize all objects
    start_time = time.time()
    deser_cc = pre.deserialize_cc(ser_cc)
    deser_alice_pk = pre.deserialize_public_key(ser_alice_pk)
    deser_alice_sk = pre.deserialize_secret_key(ser_alice_sk)
    deser_bob_pk = pre.deserialize_public_key(ser_bob_pk)
    deser_bob_sk = pre.deserialize_secret_key(ser_bob_sk)
    deser_ciphertext_alice = pre.deserialize_ciphertext(ser_ciphertext_alice)
    deser_re_key = pre.deserialize_re_encryption_key(ser_re_key)
    print(f"Deserialization time: {(time.time() - start_time) * 1000:.2f} ms")

    # 3. Perform re-encryption and decryption with deserialized objects
    print("\nRe-encrypting with deserialized objects...")
    start_time = time.time()
    deser_ciphertext_bob = pre.re_encrypt(
        deser_cc, deser_re_key, deser_ciphertext_alice
    )
    print(f"Re-encryption time: {(time.time() - start_time) * 1000:.2f} ms")

    print("\nDecrypting with deserialized objects...")
    start_time = time.time()
    final_decrypted_data = pre.decrypt(deser_cc, deser_bob_sk, deser_ciphertext_bob)
    print(f"Decryption time: {(time.time() - start_time) * 1000:.2f} ms")

    # 4. Verification
    assert original_data == final_decrypted_data, (
        "Decryption with deserialized objects failed"
    )

    print("\nSerialization/Deserialization test successful!")


if __name__ == "__main__":
    test_pre_workflow()
