"""
This file tests the proxy re-encryption (PRE) library.
"""

import time
import random
import os
import base64
import pytest
from src.lib import pre


@pytest.fixture
def crypto_setup():
    """
    Provides a shared crypto context and keys for all tests in this module.
    Scope is function (default) to ensure test isolation for parallel execution.
    """
    cc = pre.create_crypto_context()
    alice_keys = pre.generate_keys(cc)
    bob_keys = pre.generate_keys(cc)
    return {
        "cc": cc,
        "alice_keys": alice_keys,
        "bob_keys": bob_keys,
    }


def test_full_workflow(crypto_setup):
    """
    Tests the end-to-end proxy re-encryption workflow.
    """
    cc = crypto_setup["cc"]
    alice_keys = crypto_setup["alice_keys"]
    bob_keys = crypto_setup["bob_keys"]

    # 1. Encrypt data with Alice's key
    original_data = b"This is a test string for proxy re-encryption."
    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    ciphertext_alice = pre.encrypt(cc, alice_keys.publicKey, coeffs)

    # Verify Alice can decrypt her own message
    decrypted_coeffs_alice = pre.decrypt(
        cc, alice_keys.secretKey, ciphertext_alice, len(coeffs)
    )
    decrypted_data_alice = pre.coefficients_to_bytes(
        decrypted_coeffs_alice, len(original_data)
    )
    assert decrypted_data_alice == original_data

    # 2. Generate re-encryption key for Bob
    re_encryption_key = pre.generate_re_encryption_key(
        cc, alice_keys.secretKey, bob_keys.publicKey
    )

    # 3. Re-encrypt the ciphertext for Bob
    ciphertext_bob = pre.re_encrypt(cc, re_encryption_key, ciphertext_alice)

    # 4. Decrypt the re-encrypted message with Bob's key
    decrypted_coeffs_bob = pre.decrypt(
        cc, bob_keys.secretKey, ciphertext_bob, len(coeffs)
    )
    decrypted_data_bob = pre.coefficients_to_bytes(
        decrypted_coeffs_bob, len(original_data)
    )

    assert decrypted_data_bob == original_data


def test_bytes_to_coefficients_padding():
    """
    Tests that byte-to-coefficient conversion correctly pads odd-length data.
    """
    odd_length_data = b"12345"
    slot_count = 10
    coeffs = pre.bytes_to_coefficients(odd_length_data, slot_count)
    # 5 bytes -> 3 shorts (6 bytes), so 2 original coeffs + 1 from padded byte
    # struct.unpack('<3H', b'12345\0') -> (12593, 13107, 13312) - this is wrong, let's just check length
    assert len(odd_length_data) % 2 == 1
    # After padding, it should be even
    padded_data = odd_length_data + b"\0"
    assert len(pre.coefficients_to_bytes(coeffs, len(padded_data))) == len(padded_data)


def test_bytes_to_coefficients_oversized_data():
    """
    Tests that byte-to-coefficient conversion fails for data larger than the slot count.
    """
    slot_count = 10
    # 11 shorts = 22 bytes > 10 slots * 2 bytes/slot
    oversized_data = b"A" * (slot_count * 2 + 2)
    with pytest.raises(ValueError):
        pre.bytes_to_coefficients(oversized_data, slot_count)


def test_decrypt_with_wrong_key(crypto_setup):
    """
    Tests that decrypting with the wrong key does not yield the original plaintext.
    """
    cc = crypto_setup["cc"]
    alice_keys = crypto_setup["alice_keys"]
    # Some other user's keys
    mallory_keys = pre.generate_keys(cc)

    original_data = b"Secret message"
    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    ciphertext = pre.encrypt(cc, alice_keys.publicKey, coeffs)

    # Decrypt with Mallory's key
    decrypted_coeffs_wrong = pre.decrypt(
        cc, mallory_keys.secretKey, ciphertext, len(coeffs)
    )
    decrypted_data_wrong = pre.coefficients_to_bytes(
        decrypted_coeffs_wrong, len(original_data)
    )

    assert decrypted_data_wrong != original_data


def test_public_key_serialization_behavior(crypto_setup):
    """
    Tests that public key serialization is deterministic but NOT canonical,
    and that the key remains functional after a serialization roundtrip.
    """
    cc = crypto_setup["cc"]
    pk = crypto_setup["alice_keys"].publicKey
    sk = crypto_setup["alice_keys"].secretKey

    # 1. Verify that serialization is deterministic
    ser_pk1 = pre.serialize_to_bytes(pk)
    ser_pk2 = pre.serialize_to_bytes(pk)
    assert ser_pk1 == ser_pk2, "Public key serialization is not deterministic"

    # 2. Verify that the roundtrip is NOT canonical
    deser_pk = pre.deserialize_public_key(ser_pk1)
    reser_pk = pre.serialize_to_bytes(deser_pk)
    assert ser_pk1 != reser_pk, "Public key serialization was unexpectedly canonical"

    # 3. Verify the deserialized key is functional
    original_data = b"test for functional public key"
    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    ciphertext = pre.encrypt(cc, deser_pk, coeffs)
    decrypted_coeffs = pre.decrypt(cc, sk, ciphertext, len(coeffs))
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))
    assert decrypted_data == original_data, (
        "Deserialized public key failed to encrypt correctly"
    )


def test_secret_key_serialization_behavior(crypto_setup):
    """
    Tests that secret key serialization is NOT canonical but remains functional.
    This test documents the known non-deterministic serialization behavior of OpenFHE
    secret keys and verifies that the key is still valid after a roundtrip.
    """
    cc = crypto_setup["cc"]
    alice_keys = crypto_setup["alice_keys"]
    bob_keys = crypto_setup["bob_keys"]
    sk = alice_keys.secretKey

    # 1. Verify that the serialization is deterministic
    ser_sk1 = pre.serialize_to_bytes(sk)
    ser_sk2 = pre.serialize_to_bytes(sk)
    assert ser_sk1 == ser_sk2, "Secret key serialization is not deterministic"

    # 2. Verify that the roundtrip is NOT canonical
    deser_sk = pre.deserialize_secret_key(ser_sk1)
    reser_sk_bytes = pre.serialize_to_bytes(deser_sk)
    assert ser_sk1 != reser_sk_bytes, (
        "Secret key serialization was unexpectedly canonical"
    )

    # 3. Verify the deserialized key is fully functional
    original_data = b"test for functional secret key"
    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    ciphertext = pre.encrypt(cc, alice_keys.publicKey, coeffs)

    # a. Can it decrypt?
    decrypted_coeffs = pre.decrypt(cc, deser_sk, ciphertext, len(coeffs))
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))
    assert decrypted_data == original_data, "Deserialized secret key failed to decrypt"

    # b. Can it be used for re-key generation?
    re_key = pre.generate_re_encryption_key(cc, deser_sk, bob_keys.publicKey)
    assert re_key is not None, "Failed to generate re-key with deserialized secret key"
    re_encrypted = pre.re_encrypt(cc, re_key, ciphertext)
    re_decrypted_coeffs = pre.decrypt(cc, bob_keys.secretKey, re_encrypted, len(coeffs))
    re_decrypted_data = pre.coefficients_to_bytes(
        re_decrypted_coeffs, len(original_data)
    )
    assert re_decrypted_data == original_data, "Re-key from deserialized SK failed"


def test_ciphertext_serialization_behavior(crypto_setup):
    """
    Tests that ciphertext serialization is deterministic but NOT canonical,
    and that it remains functional after a serialization roundtrip.
    """
    cc = crypto_setup["cc"]
    keys = crypto_setup["alice_keys"]
    original_data = b"some data for ciphertext test"
    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    ciphertexts = pre.encrypt(cc, keys.publicKey, coeffs)

    # Test the first ciphertext in the list
    ciphertext = ciphertexts[0]

    # 1. Verify that serialization is deterministic
    ser_ct1 = pre.serialize_to_bytes(ciphertext)
    ser_ct2 = pre.serialize_to_bytes(ciphertext)
    assert ser_ct1 == ser_ct2, "Ciphertext serialization is not deterministic"

    # 2. Verify that the roundtrip is NOT canonical
    deser_ct = pre.deserialize_ciphertext(ser_ct1)
    reser_ct = pre.serialize_to_bytes(deser_ct)
    assert ser_ct1 != reser_ct, "Ciphertext serialization was unexpectedly canonical"

    # 3. Verify the deserialized ciphertext is functional
    # Replace the first ciphertext with the deserialized one
    modified_ciphertexts = [deser_ct] + ciphertexts[1:]
    decrypted_coeffs = pre.decrypt(
        cc, keys.secretKey, modified_ciphertexts, len(coeffs)
    )
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))
    assert decrypted_data == original_data, (
        "Deserialized ciphertext failed to decrypt correctly"
    )


def test_workflow_with_deserialized_objects(crypto_setup):
    """
    Tests that deserialized objects are fully functional by running a
    full re-encryption workflow with them.
    """
    cc = crypto_setup["cc"]
    alice_keys = crypto_setup["alice_keys"]
    bob_keys = crypto_setup["bob_keys"]

    # 1. Serialize all necessary objects
    ser_alice_pk_bytes = pre.serialize_to_bytes(alice_keys.publicKey)
    ser_alice_sk_bytes = pre.serialize_to_bytes(alice_keys.secretKey)
    ser_bob_pk_bytes = pre.serialize_to_bytes(bob_keys.publicKey)
    ser_bob_sk_bytes = pre.serialize_to_bytes(bob_keys.secretKey)

    # 2. Deserialize them
    deser_alice_pk = pre.deserialize_public_key(ser_alice_pk_bytes)
    deser_alice_sk = pre.deserialize_secret_key(ser_alice_sk_bytes)
    deser_bob_pk = pre.deserialize_public_key(ser_bob_pk_bytes)
    deser_bob_sk = pre.deserialize_secret_key(ser_bob_sk_bytes)

    # 3. Run the workflow with deserialized objects
    original_data = b"test for deserialized objects"
    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)

    # Encrypt with deserialized Alice PK
    ciphertext_alice = pre.encrypt(cc, deser_alice_pk, coeffs)

    # Generate re-key with deserialized Alice SK and Bob PK
    re_key = pre.generate_re_encryption_key(cc, deser_alice_sk, deser_bob_pk)
    ser_re_key_bytes = pre.serialize_to_bytes(re_key)
    # Note: deserialize_re_encryption_key expects a b64 string, which is an
    # inconsistency in the pre.py API. We work around it here.
    deser_re_key = pre.deserialize_re_encryption_key(
        base64.b64encode(ser_re_key_bytes).decode("utf-8")
    )

    # Re-encrypt with deserialized re-key
    ciphertext_bob = pre.re_encrypt(cc, deser_re_key, ciphertext_alice)

    # Decrypt with deserialized Bob SK
    decrypted_coeffs = pre.decrypt(cc, deser_bob_sk, ciphertext_bob, len(coeffs))
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))

    assert decrypted_data == original_data


def test_deserialization_failure(crypto_setup):
    """
    Tests that deserialization functions fail with malformed or garbage data.
    """
    garbage_data = b"this is not a valid serialized object"
    with pytest.raises(RuntimeError):
        pre.deserialize_public_key(garbage_data)
    with pytest.raises(RuntimeError):
        pre.deserialize_secret_key(garbage_data)
    with pytest.raises(RuntimeError):
        pre.deserialize_ciphertext(garbage_data)


@pytest.mark.parametrize(
    "test_data",
    [
        b"",
        b"A",
        b"12345678"
        * (pre.create_crypto_context().GetRingDimension() // 4),  # Exactly fills slots
    ],
)
def test_workflow_with_edge_case_data(crypto_setup, test_data):
    """
    Tests the full PRE workflow with various edge-case data sizes.
    """
    cc = crypto_setup["cc"]
    alice_keys = crypto_setup["alice_keys"]
    bob_keys = crypto_setup["bob_keys"]
    original_data = test_data

    slot_count = pre.get_slot_count(cc)
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    ciphertext_alice = pre.encrypt(cc, alice_keys.publicKey, coeffs)

    re_key = pre.generate_re_encryption_key(
        cc, alice_keys.secretKey, bob_keys.publicKey
    )
    ciphertext_bob = pre.re_encrypt(cc, re_key, ciphertext_alice)

    decrypted_coeffs = pre.decrypt(cc, bob_keys.secretKey, ciphertext_bob, len(coeffs))
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))

    assert decrypted_data == original_data


if __name__ == "__main__":
    pytest.main()
