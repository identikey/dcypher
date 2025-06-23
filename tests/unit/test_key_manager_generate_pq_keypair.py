"""Unit tests for KeyManager PQ keypair generation across all algorithms."""

import pytest
import oqs
from src.lib.key_manager import KeyManager
from .util.util import get_enabled_sigs


@pytest.mark.parametrize("algorithm", get_enabled_sigs())
def test_generate_pq_keypair(algorithm):
    """Test PQ key pair generation for all enabled algorithms."""
    pk_bytes, sk_bytes = KeyManager.generate_pq_keypair(algorithm)

    # Verify types
    assert isinstance(pk_bytes, bytes)
    assert isinstance(sk_bytes, bytes)

    # Verify keys can be used with OQS
    with oqs.Signature(algorithm, sk_bytes) as sig:
        message = b"test message"
        signature = sig.sign(message)
        assert isinstance(signature, bytes)
        assert len(signature) > 0
