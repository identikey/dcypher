# swaggerjacked with style and decomposed from https://github.com/open-quantum-safe/liboqs-python/blob/main/tests/test_kem.py
import oqs
import pytest

from .util.util import get_enabled_kems


def test_not_supported() -> None:
    """
    Tests that the appropriate error is raised for an unsupported KEM.
    """
    with pytest.raises(oqs.MechanismNotSupportedError):
        with oqs.KeyEncapsulation("unsupported_kem"):
            pass


def test_not_enabled() -> None:
    """
    Tests that the appropriate error is raised for a disabled KEM.
    """
    supported_kems = oqs.get_supported_kem_mechanisms()
    enabled_kems = oqs.get_enabled_kem_mechanisms()
    disabled_kem = next(
        (kem for kem in supported_kems if kem not in enabled_kems), None
    )

    if disabled_kem:
        with pytest.raises(oqs.MechanismNotEnabledError):
            with oqs.KeyEncapsulation(disabled_kem):
                pass


def test_python_attributes() -> None:
    """
    Tests that the Python attributes of the KEM object are correctly set.
    """
    for alg_name in get_enabled_kems():
        with oqs.KeyEncapsulation(alg_name) as kem:
            assert kem.method_name.decode() == alg_name
            assert kem.alg_version is not None
            assert 1 <= kem.claimed_nist_level <= 5
            assert kem.length_public_key > 0
            assert kem.length_secret_key > 0
            assert kem.length_ciphertext > 0
            assert kem.length_shared_secret > 0
