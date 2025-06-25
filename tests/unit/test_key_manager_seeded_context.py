"""Unit tests for KeyManager seeded PQ keypair generation with context support."""

import pytest
import hashlib
import oqs
from src.lib.key_manager import KeyManager
from .util.util import get_sigs_with_ctx_support


@pytest.mark.skip(reason="Test disabled temporarily")
@pytest.mark.parametrize("algorithm", get_sigs_with_ctx_support())
def test_seeded_key_generation_with_context(algorithm):
    """Test seeded key generation for algorithms that support context strings."""
    test_seed = hashlib.sha256(b"test_context_seed").digest()

    # Generate seeded keys
    pk_bytes, sk_bytes = KeyManager.generate_pq_keypair_from_seed(algorithm, test_seed)

    # Verify keys work with context functions
    with oqs.Signature(algorithm, sk_bytes) as sig:
        message = b"seeded message with context"
        context = b"seeded context"

        signature = sig.sign_with_ctx_str(message, context)
        assert sig.verify_with_ctx_str(message, signature, context, pk_bytes)
