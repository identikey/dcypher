# swaggerjacked with style and decomposed from https://github.com/open-quantum-safe/liboqs-python/blob/main/tests/test_sig.py
import random

import oqs
import pytest

from .util.util import get_enabled_sigs


@pytest.mark.parametrize("alg_name", get_enabled_sigs())
def test_wrong_signature(alg_name: str) -> None:
    """
    Tests that verification fails for a wrong signature.
    """
    with oqs.Signature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        wrong_signature = bytes(random.getrandbits(8) for _ in range(len(signature)))
        assert not sig.verify(message, wrong_signature, public_key)
