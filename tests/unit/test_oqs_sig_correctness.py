# swaggerjacked with style and decomposed from https://github.com/open-quantum-safe/liboqs-python/blob/main/tests/test_sig.py
import random

import oqs
import pytest

from .util.util import get_enabled_sigs, get_sigs_with_ctx_support


@pytest.mark.parametrize("alg_name", get_enabled_sigs())
def test_correctness(alg_name: str) -> None:
    """
    Tests the signature and verification for a given algorithm.
    """
    with oqs.Signature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        assert sig.verify(message, signature, public_key)


@pytest.mark.parametrize("alg_name", get_sigs_with_ctx_support())
def test_correctness_with_ctx_str(alg_name: str) -> None:
    """
    Tests the signature and verification with a context string.
    """
    with oqs.Signature(alg_name) as sig:
        message = bytes(random.getrandbits(8) for _ in range(100))
        context = b"some context"
        public_key = sig.generate_keypair()
        signature = sig.sign_with_ctx_str(message, context)
        assert sig.verify_with_ctx_str(message, signature, context, public_key)
