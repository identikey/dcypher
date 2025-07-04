import oqs
import pytest
from src.lib.pq_auth import verify_pq_signature

from .util.util import get_enabled_sigs


@pytest.mark.parametrize("alg", get_enabled_sigs())
def test_verify_pq_signature_invalid(alg: str) -> None:
    """
    Tests that an invalid post-quantum signature is correctly rejected.
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
