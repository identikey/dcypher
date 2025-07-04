import oqs
import pytest
from src.lib.pq_auth import verify_pq_signature

from .util.util import get_enabled_sigs


@pytest.mark.parametrize("alg", get_enabled_sigs())
def test_verify_pq_signature_empty_message(alg: str) -> None:
    """
    Tests that an empty message can be signed and verified.
    """
    message = b""
    with oqs.Signature(alg) as sig:
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert verify_pq_signature(public_key.hex(), signature.hex(), message, alg)
