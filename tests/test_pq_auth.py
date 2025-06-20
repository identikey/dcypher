import oqs
import pytest
from src.lib.pq_auth import verify_pq_signature, SUPPORTED_SIG_ALGS


@pytest.mark.parametrize("alg", SUPPORTED_SIG_ALGS)
def test_verify_pq_signature_valid(alg):
    message = b"This is a test message."
    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert verify_pq_signature(public_key.hex(), signature.hex(), message, alg)


@pytest.mark.parametrize("alg", SUPPORTED_SIG_ALGS)
def test_verify_pq_signature_invalid(alg):
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
    message = b"original message"
    tampered_message = b"tampered message"
    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert not verify_pq_signature(
            public_key.hex(), signature.hex(), tampered_message, alg
        )


def test_verify_pq_signature_unsupported_alg():
    assert not verify_pq_signature(
        "".encode().hex(), "".encode().hex(), "".encode(), "Kyber512"
    )


def test_verify_pq_signature_malformed_public_key():
    assert not verify_pq_signature("malformed", "signature", b"message", "Dilithium2")


def test_verify_pq_signature_malformed_signature():
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        assert not verify_pq_signature(
            public_key.hex(), "not-a-signature", b"message", "Dilithium2"
        )
