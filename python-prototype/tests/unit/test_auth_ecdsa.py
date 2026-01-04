import ecdsa
import hashlib
from dcypher.lib.auth import verify_signature


def test_verify_signature_valid():
    """
    Tests that a valid signature is correctly verified.
    A new key pair is generated, a message is signed, and the signature is
    verified using the corresponding public key. The test asserts that
    the verification is successful.
    """
    # Generate a new key pair for testing
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("uncompressed").hex()

    # Create a message and sign it
    message = b"test message"
    signature = sk.sign(message, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()

    # Verify the signature
    assert verify_signature(public_key_hex, signature_hex, message)


def test_verify_signature_invalid():
    """
    Tests that an invalid signature is correctly rejected.
    Two different key pairs are generated. A message is signed with one key,
    and an attempt is made to verify it with the other key. The test asserts
    that the verification fails.
    """
    # Generate two different key pairs
    sk1 = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk1 = sk1.get_verifying_key()
    assert vk1 is not None
    public_key_hex1 = vk1.to_string("uncompressed").hex()

    sk2 = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    # Create a message and sign it with the second key
    message = b"test message"
    signature = sk2.sign(message, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()

    # Try to verify the signature with the first public key
    assert not verify_signature(public_key_hex1, signature_hex, message)


def test_verify_signature_tampered_message():
    """
    Tests that a signature is rejected for a tampered message.
    A message is signed, then modified. The test asserts that verifying
    the original signature against the tampered message fails.
    """
    # Generate a new key pair
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("uncompressed").hex()

    # Create a message and sign it
    message = b"original message"
    signature = sk.sign(message, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()

    # Verify the signature with a different message
    tampered_message = b"tampered message"
    assert not verify_signature(public_key_hex, signature_hex, tampered_message)


def test_verify_signature_malformed_public_key():
    """
    Tests that verification fails with a malformed public key.
    A malformed public key is used to verify a signature. The test asserts
    that the verification fails.
    """
    message = b"test"
    signature = b"fakesig"
    assert not verify_signature("malformed", signature.hex(), message)


def test_verify_signature_malformed_signature():
    """
    Tests that verification fails with a malformed signature.
    A malformed signature is used to verify a message. The test asserts
    that the verification fails.
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("uncompressed").hex()
    message = b"test"
    assert not verify_signature(public_key_hex, "not-a-signature", message)


def test_verify_signature_empty_message():
    """
    Tests that an empty message can be signed and verified.
    An empty byte string is signed and then verified. The test asserts
    that the verification is successful.
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("uncompressed").hex()
    message = b""
    signature = sk.sign(message, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()
    assert verify_signature(public_key_hex, signature_hex, message)


def test_verify_signature_different_hash():
    """
    Tests that verification fails if the message was signed with a different hash function.
    The signature is created with SHA-512, but the verification function
    expects SHA-256. The test asserts that the verification fails.
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("uncompressed").hex()
    message = b"test message"
    signature = sk.sign(message, hashfunc=hashlib.sha512)
    signature_hex = signature.hex()
    assert not verify_signature(public_key_hex, signature_hex, message)


def test_verify_signature_different_curve():
    """
    Tests that verification fails if the key is from a different curve.
    A key is generated on the NIST256p curve, but the verification function
    expects a key from the SECP256k1 curve. The test asserts that the
    verification fails.
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("uncompressed").hex()
    message = b"test message"
    signature = sk.sign(message, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()
    assert not verify_signature(public_key_hex, signature_hex, message)


def test_verify_signature_compressed_public_key():
    """
    Tests that a compressed public key can be used for verification.
    A signature is created and then verified using the compressed form of the
    public key. The test asserts that the verification is successful.
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("compressed").hex()
    message = b"test message"
    signature = sk.sign(message, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()
    assert verify_signature(public_key_hex, signature_hex, message)


def test_verify_signature_invalid_hex_public_key():
    """
    Tests that verification fails with an invalid hex public key.
    An invalid hex string is provided as the public key. The test asserts
    that the verification fails.
    """
    message = b"test"
    signature = b"fakesig"
    assert not verify_signature("abc", signature.hex(), message)


def test_verify_signature_public_key_not_on_curve():
    """
    Tests that verification fails if the public key is not a point on the curve.
    A public key is provided that is a valid point on a different elliptic
    curve (NIST256p) but not on SECP256k1. The test asserts that the
    verification fails.
    """
    # This is a valid hex-encoded byte string for a public key, but it's not a point on the secp256k1 curve.
    # It's the generator for the NIST256p curve.
    public_key_hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    message = b"test message"
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    signature = sk.sign(message, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()
    assert not verify_signature(public_key_hex, signature_hex, message)
