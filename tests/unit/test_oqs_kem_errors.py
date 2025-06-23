# swaggerjacked with style and decomposed from https://github.com/open-quantum-safe/liboqs-python/blob/main/tests/test_kem.py
import random

import oqs
import pytest

from .util.util import get_enabled_kems


@pytest.mark.parametrize("alg_name", get_enabled_kems())
def test_wrong_ciphertext(alg_name: str) -> None:
    """
    Tests that the KEM implementation correctly handles a wrong ciphertext.
    """
    with oqs.KeyEncapsulation(alg_name) as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret_server = kem.encap_secret(public_key)
        wrong_ciphertext = bytes(random.getrandbits(8) for _ in range(len(ciphertext)))
        try:
            shared_secret_client = kem.decap_secret(wrong_ciphertext)
            assert shared_secret_client != shared_secret_server
        except RuntimeError:
            # This is the expected outcome for a wrong ciphertext
            pass
