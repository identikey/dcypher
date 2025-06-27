import oqs
import pytest
from lib.pq_auth import verify_pq_signature

from .util.util import get_enabled_sigs


@pytest.mark.parametrize("alg", get_enabled_sigs())
def test_verify_pq_signature_tampered_message(alg: str) -> None:
    """
    Tests that a post-quantum signature is rejected for a tampered message.
    """
    message = b"original message"
    tampered_message = b"tampered message"
    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert not verify_pq_signature(
            public_key.hex(), signature.hex(), tampered_message, alg
        )
