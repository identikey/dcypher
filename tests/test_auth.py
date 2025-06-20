import ecdsa
import hashlib
from src.lib.auth import verify_signature


def test_verify_signature_valid():
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
    message = b"test"
    signature = b"fakesig"
    assert not verify_signature("malformed", signature.hex(), message)


def test_verify_signature_malformed_signature():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key_hex = vk.to_string("uncompressed").hex()
    message = b"test"
    assert not verify_signature(public_key_hex, "not-a-signature", message)
