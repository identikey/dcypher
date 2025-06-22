import oqs
import pytest
from lib.pq_auth import verify_pq_signature

SUPPORTED_SIG_ALGS = oqs.get_enabled_sig_mechanisms()


@pytest.mark.parametrize("alg", SUPPORTED_SIG_ALGS)
def test_verify_pq_signature_valid(alg):
    """
    Tests that a valid post-quantum signature is correctly verified.
    This test is parameterized to run for all supported signature algorithms.
    It generates a key pair, signs a message, and verifies the signature.
    """
    message = b"This is a test message."
    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert verify_pq_signature(public_key.hex(), signature.hex(), message, alg)


@pytest.mark.parametrize("alg", SUPPORTED_SIG_ALGS)
def test_verify_pq_signature_invalid(alg):
    """
    Tests that an invalid post-quantum signature is correctly rejected.
    This test is parameterized to run for all supported signature algorithms.
    It generates two key pairs, signs a message with one, and attempts to
    verify it with the other's public key.
    """
    message = b"This is a test message."
    with oqs.Signature(alg) as sig1:
        public_key1 = sig1.generate_keypair()
        with oqs.Signature(alg) as sig2:
            sig2.generate_keypair()  # Generate a different key pair
            signature2 = sig2.sign(message)
            # Try to verify with the wrong public key
            assert not verify_pq_signature(
                public_key1.hex(), signature2.hex(), message, alg
            )


@pytest.mark.parametrize("alg", SUPPORTED_SIG_ALGS)
def test_verify_pq_signature_tampered_message(alg):
    """
    Tests that a post-quantum signature is rejected for a tampered message.
    This test is parameterized to run for all supported signature algorithms.
    It signs a message, then attempts to verify the signature against a
    different, tampered message.
    """
    message = b"original message"
    tampered_message = b"tampered message"
    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert not verify_pq_signature(
            public_key.hex(), signature.hex(), tampered_message, alg
        )


def test_verify_pq_signature_unsupported_alg():
    """
    Tests that verification fails with an unsupported algorithm.
    It calls the verification function with an algorithm name that is not
    in the list of supported algorithms.
    """
    assert not verify_pq_signature(
        "".encode().hex(), "".encode().hex(), "".encode(), "Kyber512"
    )


def test_verify_pq_signature_malformed_public_key():
    """
    Tests that verification fails with a malformed public key.
    It calls the verification function with a string that is not a valid
    hex-encoded public key.
    """
    assert not verify_pq_signature("malformed", "signature", b"message", "Dilithium2")


def test_verify_pq_signature_malformed_signature():
    """
    Tests that verification fails with a malformed signature.
    It calls the verification function with a string that is not a valid
    hex-encoded signature.
    """
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        assert not verify_pq_signature(
            public_key.hex(), "not-a-signature", b"message", "Dilithium2"
        )


@pytest.mark.parametrize("alg", SUPPORTED_SIG_ALGS)
def test_verify_pq_signature_empty_message(alg):
    """
    Tests that an empty message can be signed and verified.
    This test is parameterized to run for all supported signature algorithms.
    """
    message = b""
    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert verify_pq_signature(public_key.hex(), signature.hex(), message, alg)


def test_verify_pq_signature_mismatched_alg():
    """
    Tests that verification fails if the wrong algorithm is specified.
    A signature is created with Dilithium2, but verification is attempted
    with Falcon-512.
    """
    message = b"This is a test message."
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert not verify_pq_signature(
            public_key.hex(), signature.hex(), message, "Falcon-512"
        )


def test_verify_pq_signature_invalid_hex_key():
    """
    Tests that verification fails with an invalid hex public key.
    It calls the verification function with an odd-length hex string, which
    should cause a decoding error.
    """
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(b"message")
        invalid_hex_key = public_key.hex()[:-1]
        assert not verify_pq_signature(
            invalid_hex_key, signature.hex(), b"message", "Dilithium2"
        )


def test_verify_pq_signature_invalid_hex_signature():
    """
    Tests that verification fails with an invalid hex signature.
    It calls the verification function with an odd-length hex string, which
    should cause a decoding error.
    """
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(b"message")
        invalid_hex_signature = signature.hex()[:-1]
        assert not verify_pq_signature(
            public_key.hex(), invalid_hex_signature, b"message", "Dilithium2"
        )
