import oqs
from lib.pq_auth import verify_pq_signature


def test_verify_pq_signature_unsupported_alg() -> None:
    """
    Tests that verification fails with an unsupported algorithm.
    """
    assert not verify_pq_signature(
        "".encode().hex(), "".encode().hex(), "".encode(), "unsupported_alg"
    )


def test_verify_pq_signature_malformed_public_key() -> None:
    """
    Tests that verification fails with a malformed public key.
    """
    assert not verify_pq_signature("malformed", "signature", b"message", "Dilithium2")


def test_verify_pq_signature_malformed_signature() -> None:
    """
    Tests that verification fails with a malformed signature.
    """
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        assert not verify_pq_signature(
            public_key.hex(), "not-a-signature", b"message", "Dilithium2"
        )


def test_verify_pq_signature_mismatched_alg() -> None:
    """
    Tests that verification fails if the wrong algorithm is specified.
    """
    message = b"This is a test message."
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert not verify_pq_signature(
            public_key.hex(), signature.hex(), message, "Falcon-512"
        )


def test_verify_pq_signature_invalid_hex_key() -> None:
    """
    Tests that verification fails with an invalid hex public key.
    """
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(b"message")
        invalid_hex_key = public_key.hex()[:-1]
        assert not verify_pq_signature(
            invalid_hex_key, signature.hex(), b"message", "Dilithium2"
        )


def test_verify_pq_signature_invalid_hex_signature() -> None:
    """
    Tests that verification fails with an invalid hex signature.
    """
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(b"message")
        invalid_hex_signature = signature.hex()[:-1]
        assert not verify_pq_signature(
            public_key.hex(), invalid_hex_signature, b"message", "Dilithium2"
        )
