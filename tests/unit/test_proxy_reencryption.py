"""
This file tests the proxy re-encryption (PRE) library.
"""

import base64
import pytest
from lib import pre


@pytest.fixture
def crypto_setup():
    """Provides a shared crypto context and keys for all tests.

    This fixture initializes a single crypto context and generates key pairs for
    two canonical users, "Alice" and "Bob". Using a fixture ensures that each
    test function runs in isolation with a fresh set of keys, which is critical
    for preventing side effects between tests. The scope is 'function' by
    default, creating a new setup for each test.
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
    """Tests the end-to-end proxy re-encryption workflow.

    This test covers the entire standard PRE lifecycle:
    1. Alice encrypts data with her public key.
    2. Alice generates a re-encryption key for Bob.
    3. A proxy uses the re-encryption key to transform the ciphertext.
    4. Bob decrypts the transformed ciphertext with his secret key.

    It serves as a high-level integration test to ensure the core components
    of the library work together as expected.
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
    """Tests that byte-to-coefficient conversion correctly pads odd-length data.

    The data-to-coefficient packing scheme requires an even number of bytes to
    create a list of unsigned shorts. This test ensures that if the input data
    has an odd number of bytes, it is correctly padded with a null byte, and

    that this padding is handled correctly during the reverse conversion, such
    that the original data is recovered.
    """
    odd_length_data = b"12345"
    slot_count = 10
    coeffs = pre.bytes_to_coefficients(odd_length_data, slot_count)

    # The key test: can we convert back to the original data length?
    assert len(odd_length_data) % 2 == 1  # Confirm it's odd-length
    recovered_data = pre.coefficients_to_bytes(coeffs, len(odd_length_data))
    assert recovered_data == odd_length_data


def test_coefficients_to_bytes_strict_behavior():
    """Tests that coefficient-to-byte conversion fails on out-of-range values.

    The `coefficients_to_bytes` function has a `strict` mode that is enabled
    by default. This is a critical security feature to prevent data corruption
    or unexpected behavior from malformed or maliciously crafted coefficient
    lists. This test verifies that the function raises a
    `CoefficientOutOfRangeError` when it encounters a coefficient that cannot
    be represented as a 16-bit unsigned integer.
    """
    # A coefficient that is too large for an unsigned short (max 65535)
    invalid_coeffs = [100, 200, 65536, 300]
    with pytest.raises(pre.CoefficientOutOfRangeError):
        pre.coefficients_to_bytes(invalid_coeffs, 8, strict=True)

    # Also test default behavior is strict
    with pytest.raises(pre.CoefficientOutOfRangeError):
        pre.coefficients_to_bytes(invalid_coeffs, 8)


def test_decrypt_with_wrong_key(crypto_setup):
    """Tests that decrypting with an incorrect key fails.

    This is a fundamental security test. It verifies that a ciphertext
    encrypted for Alice cannot be decrypted by an unauthorized third party
    (Mallory) who has their own valid key pair but not Alice's secret key.
    The result of a failed decryption should be indistinguishable from random
    data, not the original plaintext.
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
        decrypted_coeffs_wrong, len(original_data), strict=False
    )

    assert decrypted_data_wrong != original_data


def test_public_key_serialization_behavior(crypto_setup):
    """Tests the behavior of public key serialization.

    This test documents and verifies important properties of the serialization
    process, which is crucial for storing and transmitting keys:
    1. Determinism: Serializing the same key twice produces the same bytes.
    2. Non-Canonical Roundtrip: Deserializing and then re-serializing a key
       produces a different byte representation. This is a known behavior of
       the underlying OpenFHE library.
    3. Functional Equivalence: A key remains fully functional for encryption
       after a serialization-deserialization roundtrip.
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
    """Tests the behavior of secret key serialization.

    Similar to the public key test, this verifies the properties of secret key
    serialization. It's particularly important to confirm that a deserialized
    secret key remains fully functional for both:
    a) Decrypting ciphertexts.
    b) Generating re-encryption keys.
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
    """Tests the behavior of ciphertext serialization.

    This test confirms that ciphertexts, like keys, can be serialized and
    deserialized without losing their functional properties. It verifies the
    same properties as the key serialization tests: determinism, non-canonical
    roundtrip, and functional equivalence (i.e., a deserialized ciphertext
    can still be correctly decrypted).
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


def test_cc_serialization_behavior():
    """Tests that CryptoContext serialization is functional.

    A CryptoContext contains all the cryptographic parameters for the scheme.
    Being able to serialize and deserialize it is essential for any system
    where different components (e.g., a client and a server) need to perform
    cryptographic operations using the same parameters. This test verifies
    that a deserialized context can be used to generate keys and perform a
    full encryption/decryption cycle.
    """
    # 1. Create and serialize a context
    cc1 = pre.create_crypto_context()
    # We need to generate keys to fully initialize the context before serialization
    pre.generate_keys(cc1)
    ser_cc_bytes = pre.serialize_to_bytes(cc1)
    assert isinstance(ser_cc_bytes, bytes)

    # 2. Deserialize the context
    cc2 = pre.deserialize_cc(ser_cc_bytes)

    # 3. Verify the deserialized context is functional
    # We can't directly compare cc1 and cc2, so we test by using cc2.
    slot_count = pre.get_slot_count(cc2)
    assert slot_count > 0

    # Test key generation
    alice_keys = pre.generate_keys(cc2)
    bob_keys = pre.generate_keys(cc2)
    assert alice_keys.publicKey is not None
    assert bob_keys.publicKey is not None

    # Test a simple encryption/decryption roundtrip
    original_data = b"test for functional cc"
    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    ciphertext_alice = pre.encrypt(cc2, alice_keys.publicKey, coeffs)
    decrypted_coeffs = pre.decrypt(
        cc2, alice_keys.secretKey, ciphertext_alice, len(coeffs)
    )
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))
    assert decrypted_data == original_data


def test_workflow_with_deserialized_objects(crypto_setup):
    """Tests a full workflow using only deserialized objects.

    This is a comprehensive integration test that simulates a real-world
    scenario where all cryptographic objects (keys, ciphertexts, etc.) might
    be created on one machine, serialized, sent to another, deserialized, and
    then used. It verifies that the entire PRE workflow functions correctly
    with objects that have undergone a serialization roundtrip.
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
    deser_re_key = pre.deserialize_re_encryption_key(ser_re_key_bytes)

    # Re-encrypt with deserialized re-key
    ciphertext_bob = pre.re_encrypt(cc, deser_re_key, ciphertext_alice)

    # Decrypt with deserialized Bob SK
    decrypted_coeffs = pre.decrypt(cc, deser_bob_sk, ciphertext_bob, len(coeffs))
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))

    assert decrypted_data == original_data


def test_deserialization_failure(crypto_setup):
    """Tests that deserialization functions fail gracefully with invalid data.

    A robust system must be able to handle malformed or garbage input without
    crashing. This test feeds invalid byte strings to all deserialization
    functions and asserts that they raise a `RuntimeError` (as expected from
    the underlying C++ library) instead of causing an unhandled exception or
    undefined behavior.
    """
    garbage_data = b"this is not a valid serialized object"
    with pytest.raises(RuntimeError):
        pre.deserialize_public_key(garbage_data)
    with pytest.raises(RuntimeError):
        pre.deserialize_secret_key(garbage_data)
    with pytest.raises(RuntimeError):
        pre.deserialize_ciphertext(garbage_data)
    with pytest.raises(RuntimeError):
        pre.deserialize_re_encryption_key(garbage_data)
    with pytest.raises(RuntimeError):
        pre.deserialize_cc(garbage_data)


def test_workflow_with_multi_chunk_data(crypto_setup):
    """Tests the PRE workflow with data larger than a single ciphertext.

    The library is designed to handle data of arbitrary size by splitting it
    into multiple chunks, each encrypted in a separate ciphertext. This test
    verifies that this chunking mechanism works correctly and that the data
    can be fully reconstructed after a multi-chunk re-encryption and
    decryption cycle.
    """
    cc = crypto_setup["cc"]
    alice_keys = crypto_setup["alice_keys"]
    bob_keys = crypto_setup["bob_keys"]

    slot_count = pre.get_slot_count(cc)
    # Create data that requires more than one chunk.
    # Each char is 1 byte, each coeff is 2 bytes (unsigned short).
    # So we need > slot_count * 2 bytes.
    data_size = int(slot_count * 2 * 1.5)
    original_data = b"X" * data_size

    coeffs = pre.bytes_to_coefficients(original_data, slot_count)
    assert len(coeffs) > slot_count

    ciphertext_alice = pre.encrypt(cc, alice_keys.publicKey, coeffs)
    assert len(ciphertext_alice) > 1

    re_key = pre.generate_re_encryption_key(
        cc, alice_keys.secretKey, bob_keys.publicKey
    )
    ciphertext_bob = pre.re_encrypt(cc, re_key, ciphertext_alice)

    decrypted_coeffs = pre.decrypt(cc, bob_keys.secretKey, ciphertext_bob, len(coeffs))
    decrypted_data = pre.coefficients_to_bytes(decrypted_coeffs, len(original_data))

    assert decrypted_data == original_data


@pytest.mark.parametrize(
    "data_description,test_data_func",
    [
        ("empty", lambda: b""),
        ("single_byte", lambda: b"A"),
        (
            "exactly_fills_slots",
            lambda: b"12345678" * 1000,
        ),  # Will be truncated in test
    ],
)
def test_workflow_with_edge_case_data(crypto_setup, data_description, test_data_func):
    """Tests the full PRE workflow with various edge-case data sizes.

    This parameterized test covers several boundary conditions for data size
    to ensure the system is robust:
    - Empty data (0 bytes).
    - A single byte of data.
    - Data that exactly fills the available slots in a ciphertext.
    """
    cc = crypto_setup["cc"]
    alice_keys = crypto_setup["alice_keys"]
    bob_keys = crypto_setup["bob_keys"]

    # Generate test data based on actual slot count
    slot_count = pre.get_slot_count(cc)
    if data_description == "exactly_fills_slots":
        # Create data that exactly fills the available slots
        max_bytes = slot_count * 2
        original_data = (b"12345678" * (max_bytes // 8 + 1))[:max_bytes]
    else:
        original_data = test_data_func()

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
