"""Unit tests for KeyManager PQ keypair generation with context support."""

import pytest
import oqs
from dcypher.lib.key_manager import KeyManager
from .util.util import get_sigs_with_ctx_support


@pytest.mark.parametrize("algorithm", get_sigs_with_ctx_support())
def test_pq_keypair_with_context_support(algorithm):
    """Test PQ key pair generation for algorithms that support context strings."""
    pk_bytes, sk_bytes = KeyManager.generate_pq_keypair(algorithm)

    # Verify types
    assert isinstance(pk_bytes, bytes)
    assert isinstance(sk_bytes, bytes)

    # Verify keys can be used with OQS context functions
    with oqs.Signature(algorithm, sk_bytes) as sig:
        message = b"test message with context"
        context = b"test context"

        # Test signing with context
        signature = sig.sign_with_ctx_str(message, context)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Test verification with context
        assert sig.verify_with_ctx_str(message, signature, context, pk_bytes)
